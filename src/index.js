import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';
import cors from 'cors';
import dotenv from 'dotenv';
import { v2 as cloudinary } from 'cloudinary';
import { Readable } from 'stream';
import cron from 'node-cron';
import pool from './db.js';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

// ─── LOGGER CENTRALIZADO ──────────────────────────────────────────────────────
// Cores ANSI para terminal
const C = {
  reset:  '\x1b[0m',
  gray:   '\x1b[90m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  red:    '\x1b[31m',
  cyan:   '\x1b[36m',
  orange: '\x1b[38;5;208m',
  bold:   '\x1b[1m',
};

function log(level, action, details = {}) {
  const ts   = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const color = level === 'INFO'  ? C.green
              : level === 'WARN'  ? C.yellow
              : level === 'ERROR' ? C.red
              : C.cyan;

  const detailStr = Object.entries(details)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${C.gray}${k}${C.reset}=${C.cyan}${v}${C.reset}`)
    .join(' ');

  console.log(
    `${C.gray}[${ts}]${C.reset} ${color}${C.bold}${level}${C.reset} ` +
    `${C.orange}${action}${C.reset}` +
    (detailStr ? ` ${detailStr}` : '')
  );
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Limites por plano ────────────────────────────────────────────────────────
const PLAN_LIMITS = {
  'Básico':  { tables: 10,  crm: false, monthlyReports: false, csvImport: false, apiTokens: false },
  'Pro':     { tables: 30,  crm: true,  monthlyReports: true,  csvImport: true,  apiTokens: false },
  'Premium': { tables: 9999,crm: true,  monthlyReports: true,  csvImport: true,  apiTokens: true  },
  // Sem plano cadastrado = comportamento legacy (sem restrição)
  default:   { tables: 9999,crm: true,  monthlyReports: true,  csvImport: true,  apiTokens: true  },
};

async function getPlanLimits(tenantId) {
  const result = await pool.query(
    `SELECT p.name FROM tenants t LEFT JOIN plans p ON p.id = t.plan_id WHERE t.id = $1`,
    [tenantId]
  );
  const planName = result.rows[0]?.name;
  return { limits: PLAN_LIMITS[planName] || PLAN_LIMITS.default, planName: planName || null };
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Audit Log helper ─────────────────────────────────────────────────────────
async function auditLog(tenantId, userId, userName, action, entityType, entityId, details = {}) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (tenant_id, user_id, user_name, action, entity_type, entity_id, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [tenantId, userId || null, userName || 'sistema', action, entityType, entityId || null, JSON.stringify(details)]
    );
  } catch (e) {
    console.warn('auditLog error:', e.message);
  }
}
// ─────────────────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UPLOADS_DIR = path.join(__dirname, '../../uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const imageFilter = (req, file, cb) => {
  const allowedExts = ['.png', '.jpg', '.jpeg', '.webp', '.svg'];
  const allowedMimes = ['image/png', 'image/jpg', 'image/jpeg', 'image/webp', 'image/svg+xml'];
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype.toLowerCase();
  if (allowedExts.includes(ext) || allowedMimes.includes(mime)) {
    cb(null, true);
  } else {
    cb(new Error('Apenas imagens PNG, JPG, WEBP ou SVG'));
  }
};

// Upload para logos (memória para enviar ao Cloudinary)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 3 * 1024 * 1024 }, fileFilter: imageFilter });

// Upload para fotos de produtos (memória para enviar ao Cloudinary)
const uploadProduct = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: imageFilter });

// Upload para CSV (memória)
const csvStorage = multer.memoryStorage();
const uploadCSV = multer({ storage: csvStorage, limits: { fileSize: 2 * 1024 * 1024 } });

dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Helper: upload buffer para Cloudinary
async function uploadToCloudinary(buffer, folder, publicId) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, public_id: publicId, overwrite: true, resource_type: 'image' },
      (error, result) => error ? reject(error) : resolve(result)
    );
    Readable.from(buffer).pipe(stream);
  });
}


const app = express();
app.set('trust proxy', 1); // necessário para rate-limit funcionar atrás do proxy do Render
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'mesafay_dev_secret_change_in_production';

// ─── JWT helpers ──────────────────────────────────────────────────────────────
function makeToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}

// ─── API Token hash helper ───────────────────────────────────────────────────
import crypto from 'crypto';
function hashToken(raw) { return crypto.createHash('sha256').update(raw).digest('hex'); }

// ─── requireAuth — aceita JWT de login OU API token estático ─────────────────
async function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token de autenticacao obrigatorio' });
  }
  const raw = header.split(' ')[1];

  // Tenta JWT normal primeiro
  try {
    const decoded = jwt.verify(raw, JWT_SECRET);
    // API tokens têm type='api_token' — não passam por aqui como JWT puro
    req.auth = decoded;
    req.user = { userId: decoded.userId, role: decoded.role, tenantId: decoded.tenantId };
    return next();
  } catch {
    // JWT inválido — pode ser API token estático
  }

  // Tenta como API token (hash SHA-256 no banco)
  try {
    const h = hashToken(raw);
    const result = await pool.query(
      `SELECT t.id AS tenant_id, t.name AS tenant_name, t.is_active
       FROM api_tokens at2
       JOIN tenants t ON t.id = at2.tenant_id
       WHERE at2.token_hash = $1
         AND at2.is_active = TRUE
         AND (at2.expires_at IS NULL OR at2.expires_at > NOW())
         AND t.is_active = TRUE`,
      [h]
    );
    if (!result.rows[0]) {
      return res.status(401).json({ error: 'API token invalido, revogado ou expirado' });
    }
    const row = result.rows[0];
    // Atualiza last_used_at de forma assíncrona (sem bloquear request)
    pool.query('UPDATE api_tokens SET last_used_at = NOW() WHERE token_hash = $1', [h]).catch(() => {});
    req.auth = { tenantId: row.tenant_id, role: 'ADMIN', type: 'api_token' };
    req.user = { userId: null, role: 'ADMIN', tenantId: row.tenant_id };
    log('INFO', 'API_TOKEN_USED', { tenant: row.tenant_name });
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Erro ao verificar token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.auth || req.auth.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Acesso restrito ao administrador' });
  }
  next();
}

// ─── Rate limiting ────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Muitas tentativas de login. Aguarde 1 minuto.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: function(origin, callback) {
    // Aceita sem origin (mobile, curl), localhost, vercel previews e domínio próprio
    if (!origin) return callback(null, true);
    const allowed = [
      'http://localhost:8080',
      'http://localhost:5173',
      'http://localhost:3000',
      'https://mesafay.com.br',
      'https://www.mesafay.com.br',
      'https://pedido-facil-backend.onrender.com',
      process.env.FRONTEND_URL,
      process.env.API_URL,
    ].filter(Boolean);
    if (allowed.includes(origin) || origin.endsWith('.vercel.app') || origin.endsWith('.onrender.com')) {
      return callback(null, true);
    }
    return callback(new Error('CORS: origem nao permitida'), false);
  },
  credentials: true,
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/api/docs-inject.js', express.static(path.join(__dirname, '../public/docs-inject.js')));

// ─── Swagger docs ─────────────────────────────────────────────────────────────
const swaggerSpec = {
  openapi: '3.0.0',
  info: {
    title: 'Mesafay API',
    version: '2.0.0',
    description: `## Autenticação

Esta API suporta dois tipos de token — passe um deles no header \`Authorization: Bearer {token}\`:

| Tipo | Como obter | Validade |
|---|---|---|
| **JWT de sessão** | POST /api/auth/login | 12 horas |
| **API Token** | Gerado pelo Super Admin (/super/developers) | Configurável |

**Como autorizar no Swagger UI:** clique no botão 🔒 **Authorize** (canto superior direito), cole seu token no campo \`bearerAuth\` e clique em Authorize.

Para API Token estático (começa com \`msy_\`): cole diretamente no campo bearerAuth — o sistema detecta automaticamente.`,
  },
  servers: [
    { url: process.env.API_URL || 'http://localhost:3001', description: 'Servidor atual' },
    { url: 'https://pedido-facil-backend.onrender.com', description: 'Producao' },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http', scheme: 'bearer', bearerFormat: 'JWT',
        description: 'Token JWT obtido via POST /api/auth/login (expira em 12h)',
      },
      apiToken: {
        type: 'http', scheme: 'bearer', bearerFormat: 'API Token',
        description: 'API Token estático gerado pelo Super Admin para integracoes. Formato: msy_xxxx... Nao expira por padrão. Passe no header: Authorization: Bearer msy_...',
      },
    },
    schemas: {
      Error: { type: 'object', properties: { error: { type: 'string' } } },
      ApiToken: {
        type: 'object', properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string', example: 'Integração PDV' },
          is_active: { type: 'boolean' },
          last_used_at: { type: 'string', format: 'date-time', nullable: true },
          expires_at: { type: 'string', format: 'date-time', nullable: true },
          created_at: { type: 'string', format: 'date-time' },
        }
      }
    }
  },
  security: [{ bearerAuth: [] }, { apiToken: [] }],
  paths: {
    '/api/auth/login': { post: { tags: ['Autenticacao'], summary: 'Login do administrador', security: [], description: 'Retorna um JWT válido por 12h. Use-o no botão Authorize acima.',
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['email','password'],
        properties: {
          email: { type: 'string', example: 'admin@cantinaborgo.com.br' },
          password: { type: 'string', example: 'suasenha', format: 'password' }
        } } } } },
      responses: {
        200: { description: 'OK — copie o token retornado e cole no botão Authorize', content: { 'application/json': { schema: { type: 'object', properties: {
          token: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
          tenantId: { type: 'string' }, role: { type: 'string' }
        } } } } },
        401: { description: 'Credenciais inválidas' },
        429: { description: 'Muitas tentativas — aguarde 1 minuto' },
      }
    } },

    '/api/tables': {
      get: { tags: ['Mesas'], security: [{ bearerAuth: [] }], summary: 'Listar mesas', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Lista de mesas' } } },
      post: { tags: ['Mesas'], security: [{ bearerAuth: [] }], summary: 'Criar mesa', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','code'], properties: { tenantId: { type: 'string' }, code: { type: 'string', example: '01' }, name: { type: 'string', example: 'Mesa 01' } } } } } }, responses: { 201: { description: 'Mesa criada' } } },
    },
    '/api/tables/{id}': {
      patch: { tags: ['Mesas'], security: [{ bearerAuth: [] }], summary: 'Editar mesa', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, is_active: { type: 'boolean' } } } } } }, responses: { 200: { description: 'Mesa atualizada' } } },
      delete: { tags: ['Mesas'], security: [{ bearerAuth: [] }], summary: 'Excluir mesa', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Mesa removida' } } },
    },

    '/api/products': {
      get: { tags: ['Cardapio'], security: [{ bearerAuth: [] }], summary: 'Listar produtos', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Lista de produtos' } } },
      post: { tags: ['Cardapio'], security: [{ bearerAuth: [] }], summary: 'Criar produto', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','name','price_cents'], properties: { tenantId: { type: 'string' }, name: { type: 'string' }, price_cents: { type: 'integer', example: 1500, description: 'Valor em centavos. Ex: 1500 = R$15,00' }, sector: { type: 'string', enum: ['KITCHEN','BAR'] }, description: { type: 'string' } } } } } }, responses: { 201: { description: 'Produto criado' } } },
    },
    '/api/products/{id}': {
      patch: { tags: ['Cardapio'], security: [{ bearerAuth: [] }], summary: 'Editar produto', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, price_cents: { type: 'integer' }, is_active: { type: 'boolean' } } } } } }, responses: { 200: { description: 'Produto atualizado' } } },
      delete: { tags: ['Cardapio'], security: [{ bearerAuth: [] }], summary: 'Excluir produto', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Produto desativado' } } },
    },
    '/api/products/csv-import': { post: { tags: ['Cardapio'], security: [{ bearerAuth: [] }], summary: 'Importar produtos via CSV', requestBody: { content: { 'multipart/form-data': { schema: { type: 'object', properties: { csv: { type: 'string', format: 'binary' }, tenantId: { type: 'string' } } } } } }, responses: { 200: { description: 'Importado' } } } },
    '/api/categories': {
      get: { tags: ['Cardapio'], security: [{ bearerAuth: [] }], summary: 'Listar categorias', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Categorias' } } },
      post: { tags: ['Cardapio'], security: [{ bearerAuth: [] }], summary: 'Criar categoria', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','name'], properties: { tenantId: { type: 'string' }, name: { type: 'string' }, sort_order: { type: 'integer' } } } } } }, responses: { 201: { description: 'Criada' } } },
    },

    '/api/users': {
      get: { tags: ['Equipe'], security: [{ bearerAuth: [] }], summary: 'Listar usuários (Admin)', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Lista' }, 403: { description: 'Apenas Admin' } } },
      post: { tags: ['Equipe'], security: [{ bearerAuth: [] }], summary: 'Criar usuário (Admin)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','name','email','password','role'], properties: { tenantId: { type: 'string' }, name: { type: 'string' }, email: { type: 'string' }, password: { type: 'string' }, role: { type: 'string', enum: ['MANAGER','WAITER','CASHIER','KITCHEN','BAR'] } } } } } }, responses: { 201: { description: 'Criado' } } },
    },
    '/api/users/{id}': {
      patch: { tags: ['Equipe'], security: [{ bearerAuth: [] }], summary: 'Editar usuário', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, is_active: { type: 'boolean' } } } } } }, responses: { 200: { description: 'Atualizado' } } },
      delete: { tags: ['Equipe'], security: [{ bearerAuth: [] }], summary: 'Desativar usuário', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Desativado' } } },
    },

    '/api/sessions': { get: { tags: ['Sessoes'], security: [{ bearerAuth: [] }], summary: 'Listar sessões abertas', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Sessões' } } } },
    '/api/sessions/open': { post: { tags: ['Sessoes'], security: [], summary: 'Abrir sessão (público)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['slug','tableCode'], properties: { slug: { type: 'string' }, tableCode: { type: 'string' } } } } } }, responses: { 200: { description: 'Sessão aberta' } } } },
    '/api/sessions/close': { post: { tags: ['Sessoes'], security: [{ bearerAuth: [] }], summary: 'Fechar sessão/mesa', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['sessionId','method','amountCents'], properties: { sessionId: { type: 'string' }, method: { type: 'string', enum: ['CASH','PIX','CARD','OTHER'] }, amountCents: { type: 'integer' } } } } } }, responses: { 200: { description: 'Fechada' } } } },

    '/api/orders': { get: { tags: ['Pedidos'], security: [{ bearerAuth: [] }], summary: 'Listar pedidos', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }, { name: 'sessionId', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'Pedidos' } } } },
    '/api/orders/{id}/status': { patch: { tags: ['Pedidos'], security: [{ bearerAuth: [] }], summary: 'Atualizar status do pedido', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['status'], properties: { status: { type: 'string', enum: ['PREPARING','READY','DELIVERED','CANCELLED'] } } } } } }, responses: { 200: { description: 'Atualizado' } } } },

    '/api/public/menu/{slug}': { get: { tags: ['Publico'], security: [], summary: 'Cardápio público por slug', parameters: [{ name: 'slug', in: 'path', required: true, schema: { type: 'string', example: 'cantina-do-borgo' } }], responses: { 200: { description: 'Cardápio completo do restaurante' } } } },
    '/api/public/order': { post: { tags: ['Publico'], security: [], summary: 'Criar pedido pelo QR Code (público)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','sessionId','items'], properties: { tenantId: { type: 'string' }, sessionId: { type: 'string' }, items: { type: 'array', items: { type: 'object', properties: { productId: { type: 'string' }, quantity: { type: 'integer' }, notes: { type: 'string' } } } } } } } } }, responses: { 201: { description: 'Pedido criado' } } } },
    '/api/kds/{tenantId}/{sector}': { get: { tags: ['KDS'], security: [], summary: 'Pedidos para KDS (cozinha/bar — público)', parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'sector', in: 'path', required: true, schema: { type: 'string', enum: ['kitchen','bar'] } }], responses: { 200: { description: 'Pedidos em preparo' } } } },

    '/api/comandas': {
      get: { tags: ['Comandas'], security: [{ bearerAuth: [] }], summary: 'Listar comandas da sessão', parameters: [{ name: 'sessionId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Comandas' } } },
      post: { tags: ['Comandas'], security: [], summary: 'Abrir comanda (público)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['sessionId','tenantId','name'], properties: { sessionId: { type: 'string' }, tenantId: { type: 'string' }, name: { type: 'string' }, phone: { type: 'string' } } } } } }, responses: { 201: { description: 'Comanda aberta e cliente salvo no CRM' } } },
    },
    '/api/comandas/{id}/pay': { patch: { tags: ['Comandas'], security: [{ bearerAuth: [] }], summary: 'Fechar comanda (pagar)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['method'], properties: { method: { type: 'string', enum: ['CASH','PIX','CARD','OTHER'] }, amountCents: { type: 'integer' } } } } } }, responses: { 200: { description: 'Comanda fechada' } } } },

    '/api/crm/customers': { get: { tags: ['CRM'], security: [{ bearerAuth: [] }], summary: 'Listar clientes', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }, { name: 'search', in: 'query', schema: { type: 'string' } }, { name: 'filter', in: 'query', schema: { type: 'string', enum: ['all','inactive15','inactive30','frequent','vip'] } }, { name: 'page', in: 'query', schema: { type: 'integer' } }], responses: { 200: { description: 'Clientes com paginação' } } } },
    '/api/crm/customers/{id}': {
      get: { tags: ['CRM'], security: [{ bearerAuth: [] }], summary: 'Perfil do cliente', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Perfil completo' } } },
      patch: { tags: ['CRM'], security: [{ bearerAuth: [] }], summary: 'Atualizar cliente', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, phone: { type: 'string' }, notes: { type: 'string' } } } } } }, responses: { 200: { description: 'Atualizado' } } },
      delete: { tags: ['CRM'], security: [{ bearerAuth: [] }], summary: 'Remover cliente', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Removido' } } },
    },

    '/api/reports/overview': { get: { tags: ['Relatorios'], security: [{ bearerAuth: [] }], summary: 'Visão geral financeira', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }, { name: 'from', in: 'query', schema: { type: 'string', format: 'date', example: '2026-02-01' } }, { name: 'to', in: 'query', schema: { type: 'string', format: 'date', example: '2026-02-28' } }], responses: { 200: { description: 'Faturamento, pedidos, ticket médio, top produtos' } } } },
    '/api/monthly-reports': {
      get: { tags: ['Relatorios'], security: [{ bearerAuth: [] }], summary: 'Relatórios mensais', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Lista de relatórios mensais' } } },
      post: { tags: ['Relatorios'], security: [{ bearerAuth: [] }], summary: 'Gerar relatório mensal manual', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','year','month'], properties: { tenantId: { type: 'string' }, year: { type: 'integer', example: 2026 }, month: { type: 'integer', example: 2 } } } } } }, responses: { 200: { description: 'Relatório gerado' } } },
    },

    '/api/cash-register/current': { get: { tags: ['Caixa'], security: [{ bearerAuth: [] }], summary: 'Caixa aberto atual', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Caixa aberto ou null' } } } },
    '/api/cash-register/open': { post: { tags: ['Caixa'], security: [{ bearerAuth: [] }], summary: 'Abrir caixa', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','operatorName'], properties: { tenantId: { type: 'string' }, operatorName: { type: 'string' }, openingBalance: { type: 'integer', description: 'Troco inicial em centavos' } } } } } }, responses: { 201: { description: 'Caixa aberto' } } } },
    '/api/cash-register/{id}/close': { post: { tags: ['Caixa'], security: [{ bearerAuth: [] }], summary: 'Fechar caixa', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Caixa fechado com resumo financeiro' } } } },
    '/api/cash-register/{id}/sangria': { post: { tags: ['Caixa'], security: [{ bearerAuth: [] }], summary: 'Registrar sangria', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['amountCents'], properties: { amountCents: { type: 'integer', example: 5000, description: 'Valor em centavos' }, reason: { type: 'string' } } } } } }, responses: { 200: { description: 'Sangria registrada' } } } },

    '/api/tenant/{id}': {
      get: { tags: ['Restaurante'], security: [{ bearerAuth: [] }], summary: 'Dados do restaurante', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Dados do tenant' } } },
      patch: { tags: ['Restaurante'], security: [{ bearerAuth: [] }], summary: 'Atualizar dados (Admin)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' }, phone: { type: 'string' }, address: { type: 'string' } } } } } }, responses: { 200: { description: 'Atualizado' }, 403: { description: 'Apenas Admin' } } },
    },

    '/api/waiter/tables/{tenantId}': { get: { tags: ['Garcom'], security: [], summary: 'Mesas para garçom (público)', parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Mesas disponíveis' } } } },
    '/api/waiter/login': { post: { tags: ['Garcom'], security: [], summary: 'Login garçom por PIN', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','pin'], properties: { tenantId: { type: 'string' }, pin: { type: 'string', example: '1234' } } } } } }, responses: { 200: { description: 'Autenticado — retorna JWT garçom' } } } },

    '/api/super/login': { post: { tags: ['SuperAdmin'], security: [], summary: 'Login Super Admin', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['email','password'], properties: { email: { type: 'string' }, password: { type: 'string' } } } } } }, responses: { 200: { description: 'JWT super admin (8h)' } } } },
    '/api/super/dashboard': { get: { tags: ['SuperAdmin'], security: [{ bearerAuth: [] }], summary: 'Métricas SaaS', responses: { 200: { description: 'MRR, tenants, receita' } } } },
    '/api/super/tenants': {
      get: { tags: ['SuperAdmin'], security: [{ bearerAuth: [] }], summary: 'Listar restaurantes', responses: { 200: { description: 'Todos os restaurantes' } } },
      post: { tags: ['SuperAdmin'], security: [{ bearerAuth: [] }], summary: 'Criar restaurante', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name','adminEmail','adminPassword'], properties: { name: { type: 'string' }, adminEmail: { type: 'string' }, adminPassword: { type: 'string' }, planId: { type: 'string', nullable: true }, trialDays: { type: 'integer', nullable: true } } } } } }, responses: { 201: { description: 'Restaurante criado com usuário admin' } } },
    },
    '/api/super/api-tokens': {
      get: { tags: ['API Tokens'], security: [{ bearerAuth: [] }], summary: 'Listar API Tokens de um restaurante', description: 'Somente Super Admin.', parameters: [{ name: 'tenantId', in: 'query', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Lista de tokens (sem o raw)' } } },
      post: { tags: ['API Tokens'], security: [{ bearerAuth: [] }], summary: 'Criar API Token', description: 'O campo raw_token é retornado UMA VEZ apenas. Guarde-o com segurança.',
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['tenantId','name'], properties: {
          tenantId: { type: 'string', format: 'uuid' },
          name: { type: 'string', example: 'Integração PDV' },
          expiresInDays: { type: 'integer', nullable: true, example: 365 },
        } } } } },
        responses: { 201: { description: 'Token criado — salve o raw_token!', content: { 'application/json': { schema: { type: 'object', properties: {
          raw_token: { type: 'string', example: 'msy_a1b2c3...' },
          id: { type: 'string' }, name: { type: 'string' }, is_active: { type: 'boolean' },
        } } } } } }
      },
    },
    '/api/super/api-tokens/{id}': { delete: { tags: ['API Tokens'], security: [{ bearerAuth: [] }], summary: 'Revogar token', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Token revogado' } } } },
    '/api/super/api-tokens/{id}/permanent': { delete: { tags: ['API Tokens'], security: [{ bearerAuth: [] }], summary: 'Excluir token permanentemente', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Token excluído' } } } },
    '/api/developer/info': { get: { tags: ['API Tokens'], security: [{ bearerAuth: [] }], summary: 'Info do tenant para página de docs', responses: { 200: { description: 'Dados do tenant e tokens ativos' } } } },

    '/api/health': { get: { tags: ['Sistema'], security: [], summary: 'Health check', responses: { 200: { description: 'API online' } } } },
  },
};

app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: `
    body { margin: 0; }
    .swagger-ui .topbar { background: linear-gradient(135deg,#1e2130,#2d3148) !important; padding: 8px 20px !important; }
    .swagger-ui .topbar-wrapper img { display:none; }
    .swagger-ui .topbar-wrapper { display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
    .swagger-ui .topbar-wrapper::before { content: '🍽️  Mesafay API'; color:#fff; font-size:1rem; font-weight:700; font-family:sans-serif; white-space:nowrap; }

    /* Esconde botão Authorize original */
    .swagger-ui .btn.authorize { display:none !important; }
    .swagger-ui .auth-wrapper { display:none !important; }
    .swagger-ui .authorization__btn { display:none !important; }

    /* Token bar fixo no topo */
    #msf-token-bar {
      position: sticky;
      top: 0;
      z-index: 9999;
      background: #1e2130;
      padding: 10px 20px;
      display: flex;
      align-items: center;
      gap: 10px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.3);
      font-family: sans-serif;
    }
    #msf-token-bar label {
      color: #f97316;
      font-size: 0.78rem;
      font-weight: 700;
      white-space: nowrap;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    #msf-token-input {
      flex: 1;
      background: #0f1120;
      border: 1.5px solid #f97316;
      border-radius: 8px;
      padding: 8px 14px;
      color: #fff;
      font-size: 0.82rem;
      font-family: monospace;
      outline: none;
      min-width: 0;
    }
    #msf-token-input::placeholder { color: #555; }
    #msf-token-input:focus { border-color: #fb923c; box-shadow: 0 0 0 3px rgba(249,115,22,0.2); }
    #msf-token-btn {
      background: linear-gradient(135deg,#f97316,#ea580c);
      border: none;
      border-radius: 8px;
      padding: 8px 18px;
      color: #fff;
      font-weight: 700;
      font-size: 0.82rem;
      cursor: pointer;
      white-space: nowrap;
      font-family: sans-serif;
      transition: opacity 0.15s;
    }
    #msf-token-btn:hover { opacity: 0.9; }
    #msf-token-status {
      font-size: 0.75rem;
      font-weight: 700;
      white-space: nowrap;
      transition: color 0.3s;
    }
    #msf-token-status.ok { color: #4ade80; }
    #msf-token-status.empty { color: #ef4444; }
    #msf-token-status.cleared { color: #9ca3af; }

    /* Tags e endpoints */
    .swagger-ui .info .title { color:#1e2130; font-size:2rem; }
    .swagger-ui .opblock-tag { font-size:1rem; font-weight:700; border-bottom:2px solid #f0f2f7; }
    .swagger-ui .opblock.opblock-get { border-color:#16a34a; background:rgba(22,163,74,0.03); }
    .swagger-ui .opblock.opblock-post { border-color:#2563eb; background:rgba(37,99,235,0.03); }
    .swagger-ui .opblock.opblock-patch { border-color:#d97706; background:rgba(217,119,6,0.03); }
    .swagger-ui .opblock.opblock-delete { border-color:#dc2626; background:rgba(220,38,38,0.03); }
    .swagger-ui section.models { display:none; }
    .swagger-ui .btn.try-out__btn { background:#6366f1 !important; color:#fff !important; border-color:#6366f1 !important; border-radius:6px; }
    .swagger-ui .execute-wrapper .btn.execute { background:#f97316 !important; border-color:#f97316 !important; border-radius:6px !important; font-weight:700 !important; }
    .swagger-ui .highlight-code { max-height: 400px; overflow-y: auto; }
  `,
  customSiteTitle: 'Mesafay API Docs',
  customJs: '/api/docs-inject.js',
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    filter: true,
    tryItOutEnabled: true,
    requestInterceptor: (req) => {
      const saved = localStorage.getItem('msf_api_token');
      if (saved) {
        req.headers['Authorization'] = 'Bearer ' + saved;
      }
      return req;
    },
  },
}));


app.post('/api/tenant/:id/logo', requireAuth, requireAdmin, upload.single('logo'), async (req, res) => {
  const { id } = req.params;
  if (!req.file) return res.status(400).json({ error: 'Arquivo não enviado' });
  try {
    // Remove logo anterior do Cloudinary se existir
    const old = await pool.query('SELECT logo_url FROM tenants WHERE id=$1', [id]);
    const oldUrl = old.rows[0]?.logo_url;
    if (oldUrl && oldUrl.includes('cloudinary.com')) {
      try {
        const publicId = `mesafay/logos/logo-${id}`;
        await cloudinary.uploader.destroy(publicId).catch(() => {});
      } catch {}
    }

    const result = await uploadToCloudinary(req.file.buffer, 'mesafay/logos', `logo-${id}`);
    const logoUrl = result.secure_url;
    await pool.query('UPDATE tenants SET logo_url=$1 WHERE id=$2', [logoUrl, id]);
    log('INFO', 'LOGO_ATUALIZADO', { tenantId: id });
    res.json({ logo_url: logoUrl });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao salvar logo' });
  }
});

// ─── RESEND (e-mails transacionais) ──────────────────────────────────────────
import { Resend } from 'resend';
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const FROM_EMAIL  = process.env.FROM_EMAIL  || 'Mesafay <noreply@mesafay.com.br>';
const REPLY_EMAIL = process.env.REPLY_EMAIL || 'contato@mesafay.com.br';
const FRONTEND    = process.env.FRONTEND_URL || 'https://mesafay.com.br';

async function sendWelcomeEmail({ tenantName, adminEmail, adminPassword, slug, trialDays }) {
  if (!resend) {
    console.warn('[EMAIL] RESEND_API_KEY ausente — e-mail de boas-vindas não enviado para', adminEmail);
    return;
  }

  const loginUrl  = `${FRONTEND}/login`;
  const menuUrl   = `${FRONTEND}/mesa/${slug}/1`;
  const trialText = trialDays
    ? `<p style="margin:0 0 8px">⏳ Seu período de teste é de <strong>${trialDays} dias</strong>. Aproveite!</p>`
    : '';

  await resend.emails.send({
    from:    FROM_EMAIL,
    to:      adminEmail,
    replyTo: REPLY_EMAIL,
    subject: `🎉 Bem-vindo ao Mesafay — ${tenantName}`,
    html: `
<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f6fa;font-family:'DM Sans',Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6fa;padding:40px 16px">
    <tr><td align="center">
      <table width="100%" style="max-width:540px;background:#fff;border-radius:20px;overflow:hidden;border:1px solid #e8eaf0">

        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#e8622a 0%,#f5a623 100%);padding:36px 32px;text-align:center">
            <div style="font-size:42px;margin-bottom:8px">🍽️</div>
            <h1 style="margin:0;color:#fff;font-size:1.6rem;font-weight:800;letter-spacing:-0.02em">Bem-vindo ao Mesafay!</h1>
            <p style="margin:6px 0 0;color:rgba(255,255,255,0.85);font-size:0.95rem">${tenantName} está pronto para decolar</p>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:32px">

            <p style="margin:0 0 20px;color:#374151;font-size:0.95rem;line-height:1.6">
              Olá! Seu restaurante foi criado com sucesso. Aqui estão seus dados de acesso — <strong>guarde em lugar seguro</strong>:
            </p>

            <!-- Credentials box -->
            <div style="background:#f8faff;border:1.5px solid #e0e7ff;border-radius:12px;padding:20px 24px;margin-bottom:24px">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:8px 0;border-bottom:1px solid #e8eaf0;font-size:0.82rem;color:#6b7280;width:120px">Restaurante</td>
                  <td style="padding:8px 0;border-bottom:1px solid #e8eaf0;font-size:0.88rem;font-weight:700;color:#111827">${tenantName}</td>
                </tr>
                <tr>
                  <td style="padding:8px 0;border-bottom:1px solid #e8eaf0;font-size:0.82rem;color:#6b7280">E-mail</td>
                  <td style="padding:8px 0;border-bottom:1px solid #e8eaf0;font-size:0.88rem;color:#111827">${adminEmail}</td>
                </tr>
                <tr>
                  <td style="padding:8px 0;font-size:0.82rem;color:#6b7280">Senha</td>
                  <td style="padding:8px 0;font-size:0.88rem;font-weight:700;color:#e8622a;font-family:monospace;letter-spacing:0.05em">${adminPassword}</td>
                </tr>
              </table>
            </div>

            ${trialText}

            <!-- CTA -->
            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px">
              <tr>
                <td align="center">
                  <a href="${loginUrl}" style="display:inline-block;background:linear-gradient(135deg,#e8622a,#f5a623);color:#fff;font-weight:800;font-size:0.95rem;text-decoration:none;padding:14px 36px;border-radius:12px;letter-spacing:0.02em">
                    Acessar meu painel →
                  </a>
                </td>
              </tr>
            </table>

            <!-- Steps -->
            <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:12px;padding:20px 24px;margin-bottom:24px">
              <p style="margin:0 0 12px;font-weight:700;font-size:0.9rem;color:#9a3412">📋 Próximos passos:</p>
              <ol style="margin:0;padding-left:20px;color:#7c2d12;font-size:0.85rem;line-height:1.8">
                <li>Faça login com o e-mail e senha acima</li>
                <li>Cadastre seu cardápio em <strong>Cardápio → Produtos</strong></li>
                <li>Crie suas mesas em <strong>Mesas</strong> e baixe os QR Codes</li>
                <li>Imprima e cole os QR Codes nas mesas</li>
                <li>Pronto! Seus clientes já podem pedir pelo celular</li>
              </ol>
            </div>

            <!-- Menu preview link -->
            <p style="margin:0;font-size:0.82rem;color:#6b7280;text-align:center">
              Link do seu cardápio (após cadastrar produtos):<br>
              <a href="${menuUrl}" style="color:#e8622a;font-weight:600">${menuUrl}</a>
            </p>

          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f9fafb;padding:20px 32px;text-align:center;border-top:1px solid #f0f2f7">
            <p style="margin:0;font-size:0.75rem;color:#9ca3af">
              Dúvidas? Responda este e-mail ou acesse <a href="${FRONTEND}" style="color:#e8622a">mesafay.com.br</a><br>
              <span style="color:#d1d5db">© ${new Date().getFullYear()} Mesafay. Todos os direitos reservados.</span>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
    `,
  });

  log('INFO', 'EMAIL_BOAS_VINDAS_ENVIADO', { para: adminEmail, restaurante: tenantName });
}

// POST /api/contact  — público, sem autenticação
app.post('/api/contact', async (req, res) => {
  const { name, restaurante, email, phone, mesas } = req.body;

  if (!name || !email || !restaurante) {
    return res.status(400).json({ error: 'name, email e restaurante são obrigatórios' });
  }

  // Se Resend não estiver configurado, loga e retorna sucesso (não quebra em dev)
  if (!resend) {
    console.warn('[CONTATO] RESEND_API_KEY não configurada. Dados recebidos:', req.body);
    return res.json({ ok: true, warn: 'email não enviado — RESEND_API_KEY ausente' });
  }

  try {
    await resend.emails.send({
      from: 'Mesafay <contato@mesafay.com.br>',
      to: ['contato@mesafay.com.br'],
      replyTo: email,
      subject: `🍽️ Novo lead: ${restaurante} (${name})`,
      html: `
        <div style="font-family: DM Sans, sans-serif; max-width: 520px; margin: 0 auto; background: #f4f6fa; padding: 32px;">
          <div style="background: #fff; border-radius: 16px; padding: 28px; border: 1px solid #e8eaf0;">
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid #f0f2f7;">
              <div style="width: 44px; height: 44px; border-radius: 12px; background: linear-gradient(135deg,#e8622a,#f5a623); display: flex; align-items: center; justify-content: center; font-size: 22px;">🍽️</div>
              <div>
                <p style="font-weight: 800; font-size: 1rem; color: #1e2130; margin: 0;">Novo contato via Landing Page</p>
                <p style="font-size: 0.78rem; color: #9ca3af; margin: 2px 0 0;">mesafay.com.br</p>
              </div>
            </div>

            <table style="width: 100%; border-collapse: collapse;">
              <tr><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.82rem; color: #6b7280; width: 130px;">Nome</td><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.87rem; font-weight: 600; color: #1e2130;">${name}</td></tr>
              <tr><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.82rem; color: #6b7280;">Restaurante</td><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.87rem; font-weight: 600; color: #1e2130;">${restaurante}</td></tr>
              <tr><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.82rem; color: #6b7280;">E-mail</td><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.87rem; color: #1e2130;"><a href="mailto:${email}" style="color:#e8622a;">${email}</a></td></tr>
              <tr><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.82rem; color: #6b7280;">Telefone</td><td style="padding: 10px 0; border-bottom: 1px solid #f0f2f7; font-size: 0.87rem; color: #1e2130;">${phone || '—'}</td></tr>
              <tr><td style="padding: 10px 0; font-size: 0.82rem; color: #6b7280;">Mesas</td><td style="padding: 10px 0; font-size: 0.87rem; font-weight: 600; color: #1e2130;">${mesas || '—'}</td></tr>
            </table>

            <div style="margin-top: 24px; padding: 14px 16px; background: #fff7ed; border-radius: 10px; border: 1px solid #fed7aa;">
              <p style="font-size: 0.8rem; color: #9a3412; margin: 0;">💬 Responda diretamente para <strong>${email}</strong> ou via WhatsApp.</p>
            </div>
          </div>
          <p style="text-align: center; font-size: 0.72rem; color: #d1d5db; margin-top: 20px;">© 2026 Mesafay Tecnologia</p>
        </div>
      `,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('[CONTATO] Erro ao enviar email:', err);
    res.status(500).json({ error: 'Erro ao enviar mensagem. Tente novamente.' });
  }
});

// ─── AUTH ────────────────────────────────────────────────────────────────────

// POST /api/auth/login
// Suporta login de: Admin (via tenant_login), Gerente e Garçom (via users table)
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios' });
  }

  try {
    // ── Tenta primeiro como ADMIN (tenant login) ──────────────────────────────
    const result = await pool.query(
      'SELECT tenant_login($1, $2) AS tenant_id',
      [email, password]
    );
    const tenantId = result.rows[0]?.tenant_id;

    if (tenantId) {
      // Login de admin bem-sucedido
      const tenantResult = await pool.query(
        `SELECT t.id, t.name, t.slug, t.email, t.logo_url, t.cnpj, t.phone, t.is_active, t.created_at,
                t.brand_color, t.brand_color_secondary, p.name AS plan_name
         FROM tenants t LEFT JOIN plans p ON p.id = t.plan_id WHERE t.id = $1`,
        [tenantId]
      );
      const tenant = tenantResult.rows[0];

      const userResult = await pool.query(
        `SELECT id, tenant_id, name, email, pin, role, is_active, created_at
         FROM users WHERE tenant_id = $1 AND is_active = TRUE AND role = 'ADMIN'
         ORDER BY created_at ASC LIMIT 1`,
        [tenantId]
      );
      let user = userResult.rows[0];
      if (!user) {
        const anyUser = await pool.query(
          `SELECT id, tenant_id, name, email, pin, role, is_active, created_at
           FROM users WHERE tenant_id = $1 AND is_active = TRUE LIMIT 1`,
          [tenantId]
        );
        user = anyUser.rows[0] || null;
      }
      const token = makeToken({ userId: user?.id, tenantId: tenant.id, role: user?.role || 'ADMIN' });
      log('INFO', 'LOGIN_ADMIN', { email, tenant: tenant.name, userId: user?.id });
      return res.json({ tenant, user, token });
    }

    // ── Tenta como usuário (MANAGER, WAITER, CASHIER, etc.) ──────────────────
    const userResult = await pool.query(
      `SELECT u.id, u.tenant_id, u.name, u.email, u.password_hash, u.pin, u.role, u.is_active, u.created_at
       FROM users u
       WHERE u.email = $1 AND u.is_active = TRUE
       LIMIT 1`,
      [email]
    );
    const userRow = userResult.rows[0];

    if (!userRow) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    // Apenas ADMIN e MANAGER podem acessar o painel
    if (!['ADMIN', 'MANAGER'].includes(userRow.role)) {
      return res.status(403).json({ error: 'Acesso ao painel não permitido para este cargo. Use o app do garçom.' });
    }

    const validPassword = await bcrypt.compare(password, userRow.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    if (!userRow.is_active) {
      return res.status(403).json({ error: 'Usuário inativo. Contate o administrador.' });
    }

    // Busca dados do tenant do usuário
    const tenantResult = await pool.query(
      `SELECT t.id, t.name, t.slug, t.email, t.logo_url, t.cnpj, t.phone, t.is_active, t.created_at,
              t.brand_color, t.brand_color_secondary, p.name AS plan_name
       FROM tenants t LEFT JOIN plans p ON p.id = t.plan_id WHERE t.id = $1`,
      [userRow.tenant_id]
    );
    const tenant = tenantResult.rows[0];

    const { password_hash, ...user } = userRow;
    const token = makeToken({ userId: user.id, tenantId: user.tenant_id, role: user.role });
    log('INFO', 'LOGIN_USER', { email, role: user.role, userId: user.id });
    return res.json({ tenant, user, token });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ─── RECUPERAÇÃO DE SENHA ────────────────────────────────────────────────────

// POST /api/auth/forgot-password — gera token e envia e-mail
app.post('/api/auth/forgot-password', loginLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email obrigatório' });

  // Responde sempre com sucesso para não revelar se o e-mail existe
  res.json({ ok: true, message: 'Se o e-mail existir, você receberá as instruções em instantes.' });

  try {
    const userResult = await pool.query(
      `SELECT u.id, u.name, u.email, t.name AS tenant_name
       FROM users u
       JOIN tenants t ON t.id = u.tenant_id
       WHERE u.email = $1 AND u.is_active = TRUE
       LIMIT 1`,
      [email]
    );
    const user = userResult.rows[0];
    if (!user) return; // não faz nada mas já respondeu 200

    // Gera token seguro (32 bytes = 64 chars hex)
    const rawToken  = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

    // Invalida tokens anteriores do usuário
    await pool.query(`DELETE FROM password_reset_tokens WHERE user_id = $1`, [user.id]);

    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expiresAt]
    );

    const resetUrl = `${FRONTEND}/reset-password?token=${rawToken}`;

    if (!resend) {
      console.warn('[RESET] RESEND_API_KEY ausente. URL de reset:', resetUrl);
      return;
    }

    await resend.emails.send({
      from:    FROM_EMAIL,
      to:      user.email,
      replyTo: REPLY_EMAIL,
      subject: '🔐 Redefinir senha — Mesafay',
      html: `
<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f6fa;font-family:Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6fa;padding:40px 16px">
    <tr><td align="center">
      <table width="100%" style="max-width:520px;background:#fff;border-radius:20px;overflow:hidden;border:1px solid #e8eaf0">

        <tr>
          <td style="background:linear-gradient(135deg,#e8622a 0%,#f5a623 100%);padding:32px;text-align:center">
            <div style="font-size:38px;margin-bottom:8px">🔐</div>
            <h1 style="margin:0;color:#fff;font-size:1.4rem;font-weight:800">Redefinir senha</h1>
            <p style="margin:6px 0 0;color:rgba(255,255,255,0.85);font-size:0.9rem">${user.tenant_name}</p>
          </td>
        </tr>

        <tr>
          <td style="padding:32px">
            <p style="margin:0 0 16px;color:#374151;font-size:0.95rem;line-height:1.6">
              Olá, <strong>${user.name}</strong>! Recebemos uma solicitação para redefinir a senha da sua conta.
            </p>

            <p style="margin:0 0 24px;color:#6b7280;font-size:0.88rem;line-height:1.6">
              Clique no botão abaixo para criar uma nova senha. Este link é válido por <strong>1 hora</strong>.
            </p>

            <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px">
              <tr>
                <td align="center">
                  <a href="${resetUrl}" style="display:inline-block;background:linear-gradient(135deg,#e8622a,#f5a623);color:#fff;font-weight:800;font-size:0.95rem;text-decoration:none;padding:14px 36px;border-radius:12px;letter-spacing:0.02em">
                    Criar nova senha →
                  </a>
                </td>
              </tr>
            </table>

            <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:20px">
              <p style="margin:0 0 8px;font-size:0.8rem;color:#6b7280">Ou copie e cole este link no navegador:</p>
              <p style="margin:0;font-size:0.78rem;color:#e8622a;word-break:break-all">${resetUrl}</p>
            </div>

            <p style="margin:0;font-size:0.82rem;color:#9ca3af;text-align:center">
              Se você não solicitou a redefinição, ignore este e-mail. Sua senha não será alterada.
            </p>
          </td>
        </tr>

        <tr>
          <td style="background:#f9fafb;padding:20px 32px;text-align:center;border-top:1px solid #f0f2f7">
            <p style="margin:0;font-size:0.75rem;color:#9ca3af">
              © ${new Date().getFullYear()} Mesafay • <a href="${FRONTEND}" style="color:#e8622a">mesafay.com.br</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
      `,
    });

    log('INFO', 'RESET_SENHA_SOLICITADO', { email, userId: user.id });
  } catch (e) {
    log('WARN', 'RESET_SENHA_ERRO', { msg: e?.message });
  }
});

// POST /api/auth/reset-password — valida token e salva nova senha
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'token e password são obrigatórios' });
  if (password.length < 6) return res.status(400).json({ error: 'A senha precisa ter pelo menos 6 caracteres' });

  try {
    const tokenHash = hashToken(token);
    const result = await pool.query(
      `SELECT prt.id, prt.user_id, prt.expires_at, prt.used_at
       FROM password_reset_tokens prt
       WHERE prt.token_hash = $1`,
      [tokenHash]
    );
    const row = result.rows[0];

    if (!row)                       return res.status(400).json({ error: 'Link inválido ou expirado' });
    if (row.used_at)                return res.status(400).json({ error: 'Este link já foi utilizado' });
    if (new Date() > row.expires_at) return res.status(400).json({ error: 'Link expirado. Solicite um novo.' });

    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [passwordHash, row.user_id]);
    await pool.query(`UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1`, [row.id]);

    log('INFO', 'SENHA_REDEFINIDA', { userId: row.user_id });
    res.json({ ok: true, message: 'Senha redefinida com sucesso! Faça login com a nova senha.' });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao redefinir senha' });
  }
});

// ─── TABLES ──────────────────────────────────────────────────────────────────

// GET /api/tables?tenantId=xxx
app.get('/api/tables', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT id, tenant_id, code, name, is_active, created_at FROM tables WHERE tenant_id = $1 ORDER BY code',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar mesas' });
  }
});

// POST /api/tables
app.post('/api/tables', requireAuth, async (req, res) => {
  const { tenantId, code, name } = req.body;
  if (!tenantId || !code) return res.status(400).json({ error: 'tenantId e code são obrigatórios' });

  try {
    // Verifica limite de mesas do plano
    const { limits, planName } = await getPlanLimits(tenantId);
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM tables WHERE tenant_id = $1 AND is_active = TRUE`, [tenantId]
    );
    const current = parseInt(countResult.rows[0].count);
    if (current >= limits.tables) {
      return res.status(403).json({
        error: `Limite do plano ${planName || 'atual'} atingido (${limits.tables} mesas). Faça upgrade para adicionar mais mesas.`,
        code: 'PLAN_LIMIT_TABLES',
        limit: limits.tables,
        current,
      });
    }

    const result = await pool.query(
      'INSERT INTO tables (tenant_id, code, name) VALUES ($1, $2, $3) RETURNING *',
      [tenantId, code, name || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao criar mesa' });
  }
});

// PATCH /api/tables/:id
app.patch('/api/tables/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { code, name, is_active } = req.body;

  try {
    const result = await pool.query(
      `UPDATE tables SET
        code = COALESCE($1, code),
        name = COALESCE($2, name),
        is_active = COALESCE($3, is_active)
       WHERE id = $4 RETURNING *`,
      [code, name, is_active, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Mesa não encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar mesa' });
  }
});

// DELETE /api/tables/:id
app.delete('/api/tables/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE tables SET is_active = FALSE WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao remover mesa' });
  }
});

// ─── CATEGORIES ──────────────────────────────────────────────────────────────

// GET /api/categories?tenantId=xxx
app.get('/api/categories', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT * FROM menu_categories WHERE tenant_id = $1 ORDER BY sort_order, name',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar categorias' });
  }
});

// POST /api/categories
app.post('/api/categories', requireAuth, async (req, res) => {
  const { tenantId, name, sort_order } = req.body;
  if (!tenantId || !name) return res.status(400).json({ error: 'tenantId e name são obrigatórios' });

  try {
    const result = await pool.query(
      'INSERT INTO menu_categories (tenant_id, name, sort_order) VALUES ($1, $2, $3) RETURNING *',
      [tenantId, name, sort_order || 0]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao criar categoria' });
  }
});

// PATCH /api/categories/:id
app.patch('/api/categories/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, sort_order, is_active } = req.body;

  try {
    const result = await pool.query(
      `UPDATE menu_categories SET
        name = COALESCE($1, name),
        sort_order = COALESCE($2, sort_order),
        is_active = COALESCE($3, is_active)
       WHERE id = $4 RETURNING *`,
      [name, sort_order, is_active, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Categoria não encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar categoria' });
  }
});

// DELETE /api/categories/:id
app.delete('/api/categories/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE menu_categories SET is_active = FALSE WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao remover categoria' });
  }
});

// ─── PRODUCTS ────────────────────────────────────────────────────────────────

// GET /api/products?tenantId=xxx&page=1&limit=100&sector=KITCHEN
app.get('/api/products', requireAuth, async (req, res) => {
  const { tenantId, sector, page, limit } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  const pageNum  = Math.max(1, parseInt(page)  || 1);
  const limitNum = Math.min(500, Math.max(1, parseInt(limit) || 200));
  const offset   = (pageNum - 1) * limitNum;

  try {
    const conditions = ['tenant_id = $1'];
    const params = [tenantId];
    if (sector) { conditions.push(`sector = $${params.length + 1}`); params.push(sector); }

    const where = conditions.join(' AND ');
    const [rows, countResult] = await Promise.all([
      pool.query(
        `SELECT * FROM products WHERE ${where} ORDER BY sort_order, name LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limitNum, offset]
      ),
      pool.query(`SELECT COUNT(*) FROM products WHERE ${where}`, params),
    ]);

    const total = parseInt(countResult.rows[0].count);
    res.json({
      data: rows.rows,
      pagination: { page: pageNum, limit: limitNum, total, pages: Math.ceil(total / limitNum) },
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar produtos' });
  }
});

// POST /api/products
app.post('/api/products', requireAuth, async (req, res) => {
  const { tenantId, category_id, name, description, price_cents, sector, sort_order, image_url, stock_qty } = req.body;
  if (!tenantId || !name || price_cents == null || !sector) {
    return res.status(400).json({ error: 'Campos obrigatórios: tenantId, name, price_cents, sector' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO products (tenant_id, category_id, name, description, price_cents, sector, sort_order, image_url, stock_qty)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [tenantId, category_id || null, name, description || null, price_cents, sector, sort_order || 0, image_url || null, stock_qty ?? null]
    );
    await auditLog(tenantId, req.user?.userId, req.user?.name, 'PRODUCT_CREATED', 'product', result.rows[0].id, { name, price_cents });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao criar produto' });
  }
});

// PATCH /api/products/:id
app.patch('/api/products/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { category_id, name, description, price_cents, sector, is_active, sort_order, image_url, stock_qty } = req.body;

  try {
    const result = await pool.query(
      `UPDATE products SET
        category_id = COALESCE($1, category_id),
        name = COALESCE($2, name),
        description = COALESCE($3, description),
        price_cents = COALESCE($4, price_cents),
        sector = COALESCE($5, sector),
        is_active = COALESCE($6, is_active),
        sort_order = COALESCE($7, sort_order),
        image_url = COALESCE($8, image_url),
        stock_qty = CASE WHEN $9::text = '__clear__' THEN NULL ELSE COALESCE($9::integer, stock_qty) END
       WHERE id = $10 RETURNING *`,
      [category_id, name, description, price_cents, sector, is_active, sort_order,
       image_url !== undefined ? image_url : null,
       stock_qty !== undefined ? (stock_qty === null ? '__clear__' : String(stock_qty)) : null,
       id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Produto não encontrado' });
    const tenantId = result.rows[0].tenant_id;
    await auditLog(tenantId, req.user?.userId, req.user?.name, 'PRODUCT_UPDATED', 'product', id, { name, price_cents, is_active, stock_qty });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar produto' });
  }
});

// DELETE /api/products/:id
app.delete('/api/products/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE products SET is_active = FALSE WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao remover produto' });
  }
});

// ─── USERS ───────────────────────────────────────────────────────────────────

// GET /api/users?tenantId=xxx
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT id, tenant_id, name, email, pin, role, is_active, created_at FROM users WHERE tenant_id = $1 ORDER BY name',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar usuários' });
  }
});

// POST /api/users
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { tenantId, name, email, password, pin, role } = req.body;
  if (!tenantId || !name || !role) {
    return res.status(400).json({ error: 'Campos obrigatórios: tenantId, name, role' });
  }

  try {
    const passwordHash = password
      ? await bcrypt.hash(password, 10)
      : null;

    const result = await pool.query(
      `INSERT INTO users (tenant_id, name, email, password_hash, pin, role)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, tenant_id, name, email, pin, role, is_active, created_at`,
      [tenantId, name, email || null, passwordHash, pin || null, role]
    );
    log('INFO', 'USUARIO_CRIADO', { nome: name, email, role, tenantId });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

// PATCH /api/users/:id
app.patch('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, pin, role, is_active, password } = req.body;

  try {
    let passwordHash = undefined;
    if (password) {
      passwordHash = await bcrypt.hash(password, 10);
    }

    const result = await pool.query(
      `UPDATE users SET
        name = COALESCE($1, name),
        email = COALESCE($2, email),
        pin = COALESCE($3, pin),
        role = COALESCE($4, role),
        is_active = COALESCE($5, is_active),
        password_hash = COALESCE($6, password_hash)
       WHERE id = $7
       RETURNING id, tenant_id, name, email, pin, role, is_active, created_at`,
      [name, email, pin, role, is_active, passwordHash || null, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Usuário não encontrado' });

    // Se trocou senha de um ADMIN, atualiza também tenants.password_hash
    if (password && result.rows[0].role === 'ADMIN') {
      const pgHash = (await pool.query('SELECT auth_hash_password($1) AS h', [password])).rows[0].h;
      await pool.query('UPDATE tenants SET password_hash = $1 WHERE id = $2', [pgHash, result.rows[0].tenant_id]);
    }

    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// DELETE /api/users/:id
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE users SET is_active = FALSE WHERE id = $1', [id]);
    log('WARN', 'USUARIO_REMOVIDO', { userId: id, feito_por: req.user?.userId });
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao remover usuário' });
  }
});

// ─── SESSIONS ────────────────────────────────────────────────────────────────

// GET /api/sessions?tenantId=xxx
app.get('/api/sessions', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      `SELECT * FROM table_sessions WHERE tenant_id = $1 ORDER BY opened_at DESC`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar sessões' });
  }
});

// POST /api/sessions/open  (abre sessão via QR ou garçom)
app.post('/api/sessions/open', async (req, res) => {
  const { slug, tableCode } = req.body;
  if (!slug || !tableCode) return res.status(400).json({ error: 'slug e tableCode são obrigatórios' });

  try {
    const result = await pool.query('SELECT open_table_session($1, $2) AS session_id', [slug, tableCode]);
    const sessionId = result.rows[0].session_id;

    // Fetch tenantId from the session so frontend can use it for comandas/CRM
    const tenantRes = await pool.query(
      'SELECT tenant_id FROM table_sessions WHERE id = $1', [sessionId]
    );
    const tenantId = tenantRes.rows[0]?.tenant_id || null;

    log('INFO', 'SESSAO_ABERTA', { sessionId, slug, mesa: tableCode, tenantId });
    res.json({ sessionId, tenantId });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: err.message || 'Erro ao abrir sessão' });
  }
});

// POST /api/sessions/close
app.post('/api/sessions/close', requireAuth, async (req, res) => {
  const { sessionId, closedBy, method, amountCents } = req.body;
  if (!sessionId || !method) return res.status(400).json({ error: 'sessionId e method são obrigatórios' });

  try {
    await pool.query(
      'SELECT close_table_session($1, $2, $3, $4)',
      [sessionId, closedBy || null, method, amountCents || 0]
    );

    // Busca tenant_id da sessão
    const sessRes = await pool.query('SELECT tenant_id FROM table_sessions WHERE id=$1', [sessionId]);
    const tenantId = sessRes.rows[0]?.tenant_id;

    // Registra pagamento na tabela payments (usado pelo caixa e relatórios)
    // Verifica se já existe registro para essa sessão antes de inserir
    if (tenantId && amountCents > 0) {
      const existsPay = await pool.query('SELECT id FROM payments WHERE session_id=$1', [sessionId]);
      if (existsPay.rows.length === 0) {
        await pool.query(
          `INSERT INTO payments (tenant_id, session_id, amount_cents, method, created_at)
           VALUES ($1, $2, $3, $4, NOW())`,
          [tenantId, sessionId, amountCents, method]
        );
      }
    }

    // Fecha todas as comandas abertas desta sessão
    await pool.query(`
      UPDATE comandas
      SET status = 'PAID', paid_at = NOW(), payment_method = $1
      WHERE session_id = $2 AND status = 'OPEN'
    `, [method, sessionId]);

    // Atualiza total_spent e visit stats de todos os clientes desta sessão
    await pool.query(`
      UPDATE customers c
      SET
        total_spent_cents = (
          SELECT COALESCE(SUM(oi.qty * oi.unit_price_cents), 0)
          FROM order_items oi
          JOIN orders o ON o.id = oi.order_id
          JOIN comandas cmd ON cmd.id = o.comanda_id
          WHERE cmd.customer_id = c.id AND o.status != 'CANCELLED'
        ),
        updated_at = NOW()
      WHERE c.id IN (
        SELECT DISTINCT cmd.customer_id
        FROM comandas cmd
        WHERE cmd.session_id = $1 AND cmd.customer_id IS NOT NULL
      )
    `, [sessionId]);

    log('INFO', 'SESSAO_FECHADA', { sessionId, metodo: method, valor: amountCents, feito_por: closedBy });
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: err.message || 'Erro ao fechar sessão' });
  }
});

// GET /api/orders?tenantId=xxx&page=1&limit=50&status=NEW
app.get('/api/orders', requireAuth, async (req, res) => {
  const { tenantId, status, page, limit } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  const pageNum  = Math.max(1, parseInt(page)  || 1);
  const limitNum = Math.min(200, Math.max(1, parseInt(limit) || 50));
  const offset   = (pageNum - 1) * limitNum;

  try {
    const conditions = ['tenant_id = $1'];
    const params = [tenantId];
    if (status) { conditions.push(`status = $${params.length + 1}`); params.push(status); }

    const where = conditions.join(' AND ');
    const [rows, countResult] = await Promise.all([
      pool.query(
        `SELECT * FROM orders WHERE ${where} ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limitNum, offset]
      ),
      pool.query(`SELECT COUNT(*) FROM orders WHERE ${where}`, params),
    ]);

    const total = parseInt(countResult.rows[0].count);
    res.json({
      data: rows.rows,
      pagination: { page: pageNum, limit: limitNum, total, pages: Math.ceil(total / limitNum) },
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar pedidos' });
  }
});

// POST /api/orders
app.post('/api/orders', async (req, res) => {
  const { tenantId, sessionId, createdBy, source, items, comandaId } = req.body;
  if (!tenantId || !sessionId || !source || !items?.length) {
    return res.status(400).json({ error: 'Campos obrigatórios: tenantId, sessionId, source, items' });
  }

  const client = await pool.connect();
  try {
    // Verifica estoque antes de abrir transação
    for (const item of items) {
      const stockRes = await client.query(
        'SELECT name, stock_qty FROM products WHERE id = $1 AND tenant_id = $2 AND is_active = TRUE',
        [item.product_id, tenantId]
      );
      const prod = stockRes.rows[0];
      if (!prod) { client.release(); return res.status(400).json({ error: `Produto não encontrado ou inativo` }); }
      if (prod.stock_qty !== null && prod.stock_qty < item.qty) {
        client.release();
        return res.status(400).json({ error: `"${prod.name}" sem estoque suficiente. Disponível: ${prod.stock_qty}` });
      }
    }

    await client.query('BEGIN');

    const orderResult = await client.query(
      `INSERT INTO orders (tenant_id, session_id, created_by, source, status, comanda_id)
       VALUES ($1, $2, $3, $4, 'NEW', $5) RETURNING *`,
      [tenantId, sessionId, createdBy || null, source, comandaId || null]
    );
    const order = orderResult.rows[0];

    for (const item of items) {
      await client.query(
        `INSERT INTO order_items (tenant_id, order_id, product_id, qty, unit_price_cents, notes)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [tenantId, order.id, item.product_id, item.qty, item.unit_price_cents, item.notes || null]
      );
      // Decrementa estoque se controlado
      await client.query(
        `UPDATE products SET stock_qty = stock_qty - $1 WHERE id = $2 AND stock_qty IS NOT NULL`,
        [item.qty, item.product_id]
      );
    }

    await client.query('COMMIT');

    // Notifica KDS via WebSocket
    try {
      const sectors = [...new Set(items.map(i => i.sector || 'KITCHEN'))];
      sectors.forEach(s => notifyKDS(tenantId, s, { type: 'NEW_ORDER', orderId: order.id, tenantId }));
    } catch (e) { console.warn('WS notify error:', e.message); }

    log('INFO', 'NOVO_PEDIDO', { orderId: order.id, tenantId, sessionId, source, itens: items.length });
    res.status(201).json(order);
  } catch (err) {
    await client.query('ROLLBACK');
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao criar pedido' });
  } finally {
    client.release();
  }
});

// GET /api/orders/balcao/pending?tenantId=xxx — pedidos balcão aguardando cobrança no caixa
app.get('/api/orders/balcao/pending', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    const result = await pool.query(
      `SELECT o.id, o.status, o.created_at,
              COALESCE(json_agg(json_build_object(
                'product_id', oi.product_id,
                'name', p.name,
                'qty', oi.qty,
                'unit_price_cents', oi.unit_price_cents,
                'notes', oi.notes
              ) ORDER BY oi.id), '[]') AS items,
              COALESCE(SUM(oi.qty * oi.unit_price_cents), 0) AS subtotal_cents
       FROM orders o
       JOIN order_items oi ON oi.order_id = o.id
       JOIN products p ON p.id = oi.product_id
       WHERE o.tenant_id = $1
         AND o.source = 'BALCAO'
         AND o.status NOT IN ('DELIVERED', 'CANCELLED')
       GROUP BY o.id
       ORDER BY o.created_at ASC`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao buscar pedidos balcão' });
  }
});

// POST /api/orders/balcao — pedido balcão: vai para KDS, pagamento só após entrega
app.post('/api/orders/balcao', requireAuth, async (req, res) => {
  const { tenantId, userId, items } = req.body;
  if (!tenantId || !items?.length) {
    return res.status(400).json({ error: 'tenantId e items são obrigatórios' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const orderResult = await client.query(
      `INSERT INTO orders (tenant_id, session_id, created_by, source, status)
       VALUES ($1, NULL, $2, 'BALCAO', 'NEW') RETURNING *`,
      [tenantId, userId || null]
    );
    const order = orderResult.rows[0];

    for (const item of items) {
      await client.query(
        `INSERT INTO order_items (tenant_id, order_id, product_id, qty, unit_price_cents, notes)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [tenantId, order.id, item.product_id, item.qty, item.unit_price_cents, item.notes || null]
      );
    }

    await client.query('COMMIT');

    try {
      const productIds = items.map(i => i.product_id);
      const prodResult = await pool.query(
        `SELECT DISTINCT sector FROM products WHERE id = ANY($1::uuid[])`,
        [productIds]
      );
      const sectors = prodResult.rows.map(r => r.sector).filter(Boolean);
      const sectorsToNotify = sectors.length > 0 ? sectors : ['KITCHEN'];
      sectorsToNotify.forEach(s => notifyKDS(tenantId, s, {
        type: 'NEW_ORDER', orderId: order.id, tenantId, source: 'BALCAO', priority: true,
      }));
    } catch (e) { console.warn('WS notify error:', e.message); }

    log('INFO', 'PEDIDO_BALCAO_CRIADO', { orderId: order.id, tenantId, itens: items.length });
    res.status(201).json({ ok: true, order });
  } catch (err) {
    await client.query('ROLLBACK');
    log('ERROR', 'ERRO_PEDIDO_BALCAO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao registrar pedido balcão' });
  } finally {
    client.release();
  }
});

// POST /api/orders/balcao/:id/pay — confirma entrega e registra pagamento
app.post('/api/orders/balcao/:id/pay', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { paymentMethod, serviceCharge, total_cents } = req.body;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const orderRes = await client.query(
      `SELECT o.tenant_id,
              COALESCE(SUM(oi.qty * oi.unit_price_cents), 0) AS subtotal
       FROM orders o
       JOIN order_items oi ON oi.order_id = o.id
       WHERE o.id = $1 AND o.source = 'BALCAO'
       GROUP BY o.tenant_id`,
      [id]
    );
    if (!orderRes.rows[0]) return res.status(404).json({ error: 'Pedido não encontrado' });

    const { tenant_id, subtotal } = orderRes.rows[0];
    const base    = total_cents || parseInt(subtotal);
    const service = serviceCharge ? Math.round(base * 0.1) : 0;
    const total   = base + service;

    await client.query(
      `UPDATE orders SET status = 'DELIVERED', updated_at = NOW() WHERE id = $1`, [id]
    );

    await client.query(
      `INSERT INTO payments (tenant_id, session_id, order_id, amount_cents, method, created_at)
       VALUES ($1, NULL, $2, $3, $4, NOW())`,
      [tenant_id, id, total, paymentMethod || 'CASH']
    );

    await client.query('COMMIT');

    try {
      notifyKDS(tenant_id, 'CASHIER', { type: 'BALCAO_PAID', orderId: id, total, paymentMethod });
    } catch (e) { console.warn('WS notify error:', e.message); }

    log('INFO', 'PEDIDO_BALCAO_PAGO', { orderId: id, total, paymentMethod });
    res.json({ ok: true, total });
  } catch (err) {
    await client.query('ROLLBACK');
    log('ERROR', 'ERRO_BALCAO_PAY', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao confirmar pagamento' });
  } finally {
    client.release();
  }
});

app.patch('/api/orders/:id/status', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: 'status obrigatório' });

  try {
    const prevResult = await pool.query('SELECT status, tenant_id, source FROM orders WHERE id = $1', [id]);
    if (!prevResult.rows[0]) return res.status(404).json({ error: 'Pedido não encontrado' });
    const prevStatus = prevResult.rows[0].status;
    const tenantId  = prevResult.rows[0].tenant_id;
    const source    = prevResult.rows[0].source;

    const result = await pool.query(
      'UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [status, id]
    );
    const updatedOrder = result.rows[0];

    // Audit log (rastreia quem cancelou ou alterou status)
    await auditLog(tenantId, req.user?.userId, req.user?.name, 'ORDER_STATUS_CHANGED', 'order', id,
      { from: prevStatus, to: status });

    // Notifica KDS da mudança de status
    try {
      ['KITCHEN','BAR'].forEach(s => notifyKDS(tenantId, s, { type: 'STATUS_CHANGE', orderId: id, status, tenantId }));
      if (source === 'BALCAO' && status === 'READY') {
        notifyKDS(tenantId, 'CASHIER', { type: 'BALCAO_READY', orderId: id, tenantId });
      }
    } catch (e) { console.warn('WS notify error:', e.message); }

    log('INFO', 'STATUS_PEDIDO', { orderId: id, status, from: prevStatus });
    res.json(updatedOrder);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar pedido' });
  }
});

// ─── ORDER ITEMS ─────────────────────────────────────────────────────────────

// GET /api/order-items?tenantId=xxx
app.get('/api/order-items', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT * FROM order_items WHERE tenant_id = $1',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar itens' });
  }
});

// ─── AUDIT LOG ───────────────────────────────────────────────────────────────

// GET /api/audit-logs?tenantId=xxx&page=1&limit=50&entityType=order
app.get('/api/audit-logs', requireAuth, async (req, res) => {
  const { tenantId, entityType, entityId, page, limit } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  const pageNum  = Math.max(1, parseInt(page)  || 1);
  const limitNum = Math.min(200, Math.max(1, parseInt(limit) || 50));
  const offset   = (pageNum - 1) * limitNum;

  try {
    const conditions = ['tenant_id = $1'];
    const params = [tenantId];
    if (entityType) { conditions.push(`entity_type = $${params.length + 1}`); params.push(entityType); }
    if (entityId)   { conditions.push(`entity_id   = $${params.length + 1}`); params.push(entityId); }

    const where = conditions.join(' AND ');
    const [rows, countResult] = await Promise.all([
      pool.query(
        `SELECT * FROM audit_logs WHERE ${where} ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limitNum, offset]
      ),
      pool.query(`SELECT COUNT(*) FROM audit_logs WHERE ${where}`, params),
    ]);

    const total = parseInt(countResult.rows[0].count);
    res.json({
      data: rows.rows,
      pagination: { page: pageNum, limit: limitNum, total, pages: Math.ceil(total / limitNum) },
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao buscar logs' });
  }
});

// ─── ADICIONAIS DE PRODUTO ────────────────────────────────────────────────────

// GET /api/product-addons?productId=xxx  — lista grupos e itens do produto
app.get('/api/product-addons', requireAuth, async (req, res) => {
  const { productId, tenantId } = req.query;
  if (!productId && !tenantId) return res.status(400).json({ error: 'productId ou tenantId obrigatório' });

  try {
    const conditions = [];
    const params = [];
    if (productId) { conditions.push(`g.product_id = $${params.length + 1}`); params.push(productId); }
    if (tenantId)  { conditions.push(`g.tenant_id  = $${params.length + 1}`); params.push(tenantId); }

    const groups = await pool.query(
      `SELECT g.*,
        COALESCE(json_agg(
          json_build_object('id', i.id, 'name', i.name, 'price_cents', i.price_cents, 'is_active', i.is_active, 'sort_order', i.sort_order)
          ORDER BY i.sort_order, i.name
        ) FILTER (WHERE i.id IS NOT NULL AND i.is_active = TRUE), '[]') AS items
       FROM product_addon_groups g
       LEFT JOIN product_addon_items i ON i.group_id = g.id
       WHERE ${conditions.join(' AND ')}
       GROUP BY g.id
       ORDER BY g.sort_order, g.name`,
      params
    );
    res.json(groups.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao buscar adicionais' });
  }
});

// POST /api/product-addons/groups  — cria grupo de adicional
app.post('/api/product-addons/groups', requireAuth, async (req, res) => {
  const { tenantId, productId, name, required, maxSelect, sortOrder } = req.body;
  if (!tenantId || !productId || !name) return res.status(400).json({ error: 'tenantId, productId e name obrigatórios' });
  try {
    const result = await pool.query(
      `INSERT INTO product_addon_groups (tenant_id, product_id, name, required, max_select, sort_order)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [tenantId, productId, name, required || false, maxSelect || 1, sortOrder || 0]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao criar grupo de adicional' });
  }
});

// PATCH /api/product-addons/groups/:id
app.patch('/api/product-addons/groups/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, required, maxSelect, sortOrder } = req.body;
  try {
    const result = await pool.query(
      `UPDATE product_addon_groups SET
        name       = COALESCE($1, name),
        required   = COALESCE($2, required),
        max_select = COALESCE($3, max_select),
        sort_order = COALESCE($4, sort_order)
       WHERE id = $5 RETURNING *`,
      [name, required, maxSelect, sortOrder, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Grupo não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao atualizar grupo' });
  }
});

// DELETE /api/product-addons/groups/:id
app.delete('/api/product-addons/groups/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM product_addon_groups WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao remover grupo' });
  }
});

// POST /api/product-addons/items  — cria item de adicional
app.post('/api/product-addons/items', requireAuth, async (req, res) => {
  const { tenantId, groupId, name, priceCents, sortOrder } = req.body;
  if (!tenantId || !groupId || !name) return res.status(400).json({ error: 'tenantId, groupId e name obrigatórios' });
  try {
    const result = await pool.query(
      `INSERT INTO product_addon_items (tenant_id, group_id, name, price_cents, sort_order)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [tenantId, groupId, name, priceCents || 0, sortOrder || 0]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao criar item de adicional' });
  }
});

// PATCH /api/product-addons/items/:id
app.patch('/api/product-addons/items/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, priceCents, isActive, sortOrder } = req.body;
  try {
    const result = await pool.query(
      `UPDATE product_addon_items SET
        name        = COALESCE($1, name),
        price_cents = COALESCE($2, price_cents),
        is_active   = COALESCE($3, is_active),
        sort_order  = COALESCE($4, sort_order)
       WHERE id = $5 RETURNING *`,
      [name, priceCents, isActive, sortOrder, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Item não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao atualizar item' });
  }
});

// DELETE /api/product-addons/items/:id
app.delete('/api/product-addons/items/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM product_addon_items WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao remover item' });
  }
});

// ─── ESTOQUE ─────────────────────────────────────────────────────────────────

// GET /api/stock?tenantId=xxx  — lista produtos com controle de estoque
app.get('/api/stock', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    const result = await pool.query(
      `SELECT id, name, sector, price_cents, stock_qty, is_active
       FROM products WHERE tenant_id = $1 AND stock_qty IS NOT NULL
       ORDER BY sector, name`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao buscar estoque' });
  }
});

// PATCH /api/stock/:productId  — ajusta estoque manualmente
app.patch('/api/stock/:productId', requireAuth, async (req, res) => {
  const { productId } = req.params;
  const { stock_qty, operation } = req.body; // operation: 'set' | 'add' | 'subtract'
  try {
    let sql;
    if (operation === 'add') {
      sql = `UPDATE products SET stock_qty = COALESCE(stock_qty, 0) + $1 WHERE id = $2 RETURNING *`;
    } else if (operation === 'subtract') {
      sql = `UPDATE products SET stock_qty = GREATEST(0, COALESCE(stock_qty, 0) - $1) WHERE id = $2 RETURNING *`;
    } else {
      sql = `UPDATE products SET stock_qty = $1 WHERE id = $2 RETURNING *`;
    }
    const result = await pool.query(sql, [stock_qty, productId]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Produto não encontrado' });
    await auditLog(result.rows[0].tenant_id, req.user?.userId, req.user?.name, 'STOCK_ADJUSTED', 'product', productId,
      { stock_qty, operation: operation || 'set' });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao ajustar estoque' });
  }
});

// ─── IMPRESSÃO DE TICKET (para impressora térmica via bridge) ─────────────────

// GET /api/orders/:id/print-ticket  — retorna texto formatado ESC/POS-style para impressão
app.get('/api/orders/:id/print-ticket', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const orderRes = await pool.query(
      `SELECT o.id, o.status, o.source, o.created_at, o.table_code,
              t.name AS tenant_name,
              COALESCE(json_agg(
                json_build_object('name', p.name, 'qty', oi.qty, 'notes', oi.notes, 'price_cents', oi.unit_price_cents)
                ORDER BY oi.id
              ), '[]') AS items
       FROM orders o
       JOIN tenants t ON t.id = o.tenant_id
       JOIN order_items oi ON oi.order_id = o.id
       JOIN products p ON p.id = oi.product_id
       WHERE o.id = $1
       GROUP BY o.id, t.name`,
      [id]
    );
    if (!orderRes.rows[0]) return res.status(404).json({ error: 'Pedido não encontrado' });
    const order = orderRes.rows[0];
    const time  = new Date(order.created_at).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
    const date  = new Date(order.created_at).toLocaleDateString('pt-BR');

    const lines = [
      '================================',
      `  ${order.tenant_name.toUpperCase()}`,
      '================================',
      `Mesa: ${order.table_code || (order.source === 'BALCAO' ? 'BALCAO' : '?')}`,
      `Hora: ${time}  Data: ${date}`,
      `Pedido: ${order.id.slice(0,8).toUpperCase()}`,
      '--------------------------------',
      ...order.items.map(i =>
        `${i.qty}x ${i.name}${i.notes ? `\n   * ${i.notes}` : ''}`
      ),
      '================================',
      '',
    ];

    res.json({ orderId: id, text: lines.join('\n'), lines });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) });
    res.status(500).json({ error: 'Erro ao gerar ticket' });
  }
});

// ─── HEALTH CHECK ────────────────────────────────────────────────────────────

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', db: 'disconnected', error: err.message });
  }
});


// ─── Migration automática — garante colunas novas no banco ───────────────────
async function runMigrations() {
  // kitchen_closed: bloqueia pedidos do cliente quando TRUE
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS kitchen_closed BOOLEAN DEFAULT FALSE`).catch(() => {});
  const migrations = [
    // Colunas novas na tabela cash_registers
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS closing_balance_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS expected_balance_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS difference_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS closing_notes TEXT`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS total_cash_in_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS total_pix_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS total_card_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS total_other_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS total_sangria_cents INTEGER DEFAULT 0`,
    `ALTER TABLE cash_registers ADD COLUMN IF NOT EXISTS total_revenue_cents INTEGER DEFAULT 0`,
    // Tabela de API Tokens (acesso programático por restaurante)
    `CREATE TABLE IF NOT EXISTS api_tokens (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      token_hash  TEXT NOT NULL,
      last_used_at TIMESTAMPTZ,
      created_by  TEXT,
      is_active   BOOLEAN DEFAULT TRUE,
      expires_at  TIMESTAMPTZ,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id)`,
    `CREATE INDEX IF NOT EXISTS idx_api_tokens_hash   ON api_tokens(token_hash)`,
    // Coluna order_id em payments para pedidos balcão (sem session_id)
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS order_id UUID REFERENCES orders(id) ON DELETE SET NULL`,
    `ALTER TABLE payments ALTER COLUMN session_id DROP NOT NULL`,
    // Pedidos balcão: session_id pode ser NULL
    `ALTER TABLE orders ALTER COLUMN session_id DROP NOT NULL`,
    // Pedidos balcão: remove check constraint de source para permitir BALCAO
    `ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_source_check`,
    // Estoque nos produtos (NULL = sem controle de estoque)
    `ALTER TABLE products ADD COLUMN IF NOT EXISTS stock_qty INTEGER DEFAULT NULL`,
    // Tabela de log de auditoria
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id   UUID REFERENCES tenants(id) ON DELETE CASCADE,
      user_id     UUID,
      user_name   TEXT,
      action      TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id   UUID,
      details     JSONB DEFAULT '{}',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id, created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id)`,
    // Grupos de adicionais para produtos (ex: "Ponto da carne", "Extras")
    `CREATE TABLE IF NOT EXISTS product_addon_groups (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      product_id  UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      required    BOOLEAN DEFAULT FALSE,
      max_select  INTEGER DEFAULT 1,
      sort_order  INTEGER DEFAULT 0,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    // Itens de cada grupo de adicional (ex: "Mal passado", "Queijo extra")
    `CREATE TABLE IF NOT EXISTS product_addon_items (
      id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
      group_id     UUID NOT NULL REFERENCES product_addon_groups(id) ON DELETE CASCADE,
      name         TEXT NOT NULL,
      price_cents  INTEGER DEFAULT 0,
      is_active    BOOLEAN DEFAULT TRUE,
      sort_order   INTEGER DEFAULT 0,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    )`,
    // Adicionais escolhidos por item de pedido
    `CREATE TABLE IF NOT EXISTS order_item_addons (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      order_item_id   UUID NOT NULL REFERENCES order_items(id) ON DELETE CASCADE,
      addon_item_id   UUID NOT NULL REFERENCES product_addon_items(id) ON DELETE CASCADE,
      name            TEXT NOT NULL,
      price_cents     INTEGER DEFAULT 0
    )`,
    `CREATE INDEX IF NOT EXISTS idx_addon_groups_product ON product_addon_groups(product_id)`,
    `CREATE INDEX IF NOT EXISTS idx_addon_items_group   ON product_addon_items(group_id)`,
    // Tokens de recuperação de senha
    `CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at    TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_pwd_reset_token ON password_reset_tokens(token_hash)`,
    // Cores de personalização por tenant
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS brand_color TEXT DEFAULT '#f97316'`,
    `ALTER TABLE tenants ADD COLUMN IF NOT EXISTS brand_color_secondary TEXT DEFAULT '#ffffff'`,
  ];
  for (const sql of migrations) {
    try { await pool.query(sql); } catch (e) { console.warn('Migration skip:', e.message); }
  }
  console.log('✅ Migrations aplicadas');
}

runMigrations().catch(console.error);

// ─── HTTP + WebSocket Server ──────────────────────────────────────────────────
const httpServer = createServer(app);

const wss = new WebSocketServer({ server: httpServer });

// Clientes conectados: Map<tenantId, Set<WebSocket>>
const wsClients = new Map();

wss.on('connection', (ws, req) => {
  // URL: /ws?tenantId=xxx&sector=KITCHEN
  const url = new URL(req.url, 'http://localhost');
  const tenantId = url.searchParams.get('tenantId');
  const sector = url.searchParams.get('sector')?.toUpperCase();

  if (!tenantId) { ws.close(); return; }

  const key = `${tenantId}:${sector || 'ALL'}`;
  if (!wsClients.has(key)) wsClients.set(key, new Set());
  wsClients.get(key).add(ws);

  console.log(`📡 WS conectado: ${key} (total: ${wsClients.get(key).size})`);

  ws.on('close', () => {
    wsClients.get(key)?.delete(ws);
    console.log(`📡 WS desconectado: ${key}`);
  });

  ws.on('error', () => wsClients.get(key)?.delete(ws));

  // Ping/pong para manter conexão viva no Render
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});

// Heartbeat a cada 30s para evitar timeout
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// Função global para notificar clientes KDS
export function notifyKDS(tenantId, sector, event) {
  const payload = JSON.stringify(event);
  // Notifica o setor específico e ALL
  [`${tenantId}:${sector}`, `${tenantId}:ALL`].forEach(key => {
    wsClients.get(key)?.forEach(ws => {
      if (ws.readyState === 1) ws.send(payload);
    });
  });
}

if (process.env.NODE_ENV !== 'test') {
  httpServer.listen(PORT, '0.0.0.0', () => {
    log('INFO', 'SERVIDOR_INICIADO', { porta: PORT, env: process.env.NODE_ENV || 'development' });
    console.log(`🚀 Backend rodando na porta ${PORT}`);
    console.log(`📡 WebSocket disponível em /ws`);
  });
}

export default app;

// ─── ROTAS PÚBLICAS (cliente via QR Code) ─────────────────────────────────────

// GET /api/public/tenant-info/:id — info básica do tenant (público, para KDS/garçom/caixa)
app.get('/api/public/tenant-info/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'SELECT id, name, logo_url, brand_color, brand_color_secondary FROM tenants WHERE id = $1 AND is_active = TRUE',
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Restaurante não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erro' });
  }
});

// GET /api/public/menu/:slug  — retorna cardápio do restaurante sem autenticação
app.get('/api/public/menu/:slug', async (req, res) => {
  const { slug } = req.params;
  try {
    const tenantResult = await pool.query(
      'SELECT id, name, logo_url, description, kitchen_closed, brand_color, brand_color_secondary FROM tenants WHERE slug = $1 AND is_active = TRUE',
      [slug]
    );
    const tenant = tenantResult.rows[0];
    if (!tenant) return res.status(404).json({ error: 'Restaurante não encontrado' });

    const [productsResult, categoriesResult] = await Promise.all([
      pool.query(
        'SELECT * FROM products WHERE tenant_id = $1 AND is_active = TRUE ORDER BY sort_order, name',
        [tenant.id]
      ),
      pool.query(
        'SELECT * FROM menu_categories WHERE tenant_id = $1 AND is_active = TRUE ORDER BY sort_order, name',
        [tenant.id]
      ),
    ]);

    res.json({
      tenantId: tenant.id,
      tenantName: tenant.name,
      tenantLogo: tenant.logo_url || null,
      tenantDescription: tenant.description || null,
      kitchenClosed: tenant.kitchen_closed || false,
      brandColor: tenant.brand_color || '#f97316',
      brandColorSecondary: tenant.brand_color_secondary || '#ffffff',
      products: productsResult.rows,
      categories: categoriesResult.rows,
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar cardápio' });
  }
});

// POST /api/public/order  — cliente envia pedido via QR Code
app.post('/api/public/order', async (req, res) => {
  const { sessionId, items, comandaId } = req.body;
  if (!sessionId || !items?.length) {
    return res.status(400).json({ error: 'sessionId e items são obrigatórios' });
  }

  const client = await pool.connect();
  try {
    // Busca tenant pelo sessionId
    const sessionResult = await client.query(
      'SELECT tenant_id FROM table_sessions WHERE id = $1 AND status = $2',
      [sessionId, 'OPEN']
    );
    const session = sessionResult.rows[0];
    if (!session) return res.status(404).json({ error: 'Sessão inválida ou encerrada' });

    // Verifica se a cozinha está fechada
    const tenantCheck = await client.query(
      'SELECT kitchen_closed FROM tenants WHERE id = $1', [session.tenant_id]
    );
    if (tenantCheck.rows[0]?.kitchen_closed) {
      client.release();
      return res.status(403).json({ error: 'Cozinha fechada. Novos pedidos não são aceitos no momento.' });
    }

    // Verifica estoque antes de abrir transação
    for (const item of items) {
      const stockRes = await client.query(
        'SELECT name, stock_qty FROM products WHERE id = $1 AND tenant_id = $2 AND is_active = TRUE',
        [item.product_id, session.tenant_id]
      );
      const prod = stockRes.rows[0];
      if (!prod) { client.release(); return res.status(400).json({ error: `Produto não encontrado ou inativo` }); }
      if (prod.stock_qty !== null && prod.stock_qty < item.qty) {
        client.release();
        return res.status(400).json({ error: `"${prod.name}" sem estoque suficiente. Disponível: ${prod.stock_qty}` });
      }
    }

    await client.query('BEGIN');

    const orderResult = await client.query(
      `INSERT INTO orders (tenant_id, session_id, source, status, comanda_id)
       VALUES ($1, $2, 'CUSTOMER', 'NEW', $3) RETURNING *`,
      [session.tenant_id, sessionId, comandaId || null]
    );
    const order = orderResult.rows[0];

    for (const item of items) {
      await client.query(
        `INSERT INTO order_items (tenant_id, order_id, product_id, qty, unit_price_cents, notes)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [session.tenant_id, order.id, item.product_id, item.qty, item.unit_price_cents, item.notes || null]
      );
      // Decrementa estoque se controlado
      await client.query(
        `UPDATE products SET stock_qty = stock_qty - $1 WHERE id = $2 AND stock_qty IS NOT NULL`,
        [item.qty, item.product_id]
      );
    }

    // Update customer total_spent if comanda has a customer linked
    if (comandaId) {
      await client.query(`
        UPDATE customers c
        SET total_spent_cents = (
          SELECT COALESCE(SUM(oi.qty * oi.unit_price_cents), 0)
          FROM order_items oi
          JOIN orders o ON o.id = oi.order_id
          JOIN comandas cmd ON cmd.id = o.comanda_id
          WHERE cmd.customer_id = c.id AND o.status != 'CANCELLED'
        ), updated_at = NOW()
        FROM comandas cmd
        WHERE cmd.id = $1 AND cmd.customer_id = c.id
      `, [comandaId]);
    }

    await client.query('COMMIT');

    // Notifica KDS via WebSocket (pedido do cliente via QR)
    try {
      const productSectors = await pool.query(
        'SELECT DISTINCT sector FROM products WHERE id = ANY($1::uuid[])',
        [items.map(i => i.product_id)]
      );
      productSectors.rows.forEach(r => notifyKDS(session.tenant_id, r.sector, { type: 'NEW_ORDER', orderId: order.id, tenantId: session.tenant_id }));
    } catch (e) { console.warn('WS notify error:', e.message); }

    log('INFO', 'PEDIDO_CLIENTE_QR', { orderId: order.id, sessionId, tenantId: session.tenant_id, itens: items.length });
    res.status(201).json({ orderId: order.id });
  } catch (err) {
    await client.query('ROLLBACK');
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao registrar pedido' });
  } finally {
    client.release();
  }
});

// GET /api/public/session/:sessionId/orders — pedidos da sessão para o cliente
app.get('/api/public/session/:sessionId/orders', async (req, res) => {
  // Sanitiza sessionId — remove vírgulas e espaços caso venha malformado
  const sessionId = req.params.sessionId.split(',')[0].trim();
  if (!sessionId || !/^[0-9a-f-]{36}$/.test(sessionId)) {
    return res.status(400).json({ error: 'sessionId inválido' });
  }
  try {
    // Verifica se a sessão existe
    const sessionResult = await pool.query(
      'SELECT id, tenant_id FROM table_sessions WHERE id = $1',
      [sessionId]
    );
    if (!sessionResult.rows[0]) return res.status(404).json({ error: 'Sessão não encontrada' });

    // Busca pedidos com itens e nomes dos produtos
    const ordersResult = await pool.query(
      `SELECT o.id, o.status, o.source, o.created_at, o.updated_at,
              json_agg(
                json_build_object(
                  'id', oi.id,
                  'product_id', oi.product_id,
                  'product_name', p.name,
                  'qty', oi.qty,
                  'unit_price_cents', oi.unit_price_cents,
                  'notes', oi.notes
                ) ORDER BY oi.id
              ) AS items
       FROM orders o
       JOIN order_items oi ON oi.order_id = o.id
       JOIN products p ON p.id = oi.product_id
       WHERE o.session_id = $1
       GROUP BY o.id
       ORDER BY o.created_at DESC`,
      [sessionId]
    );
    res.json(ordersResult.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar pedidos' });
  }
});

// ─── BILL REQUESTS ────────────────────────────────────────────────────────────

// POST /api/public/bill-request  — cliente solicita fechamento de conta
app.post('/api/public/bill-request', async (req, res) => {
  const { sessionId } = req.body;
  if (!sessionId) return res.status(400).json({ error: 'sessionId obrigatório' });
  try {
    const sessionResult = await pool.query(
      'SELECT tenant_id FROM table_sessions WHERE id = $1 AND status = $2',
      [sessionId, 'OPEN']
    );
    const session = sessionResult.rows[0];
    if (!session) return res.status(404).json({ error: 'Sessão inválida ou já fechada' });

    // Verifica se já existe solicitação pendente antes de inserir
    const existing = await pool.query(
      `SELECT id FROM bill_requests WHERE session_id = $1 AND status = 'PENDING'`,
      [sessionId]
    );
    if (!existing.rows[0]) {
      await pool.query(
        `INSERT INTO bill_requests (tenant_id, session_id, status) VALUES ($1, $2, 'PENDING')`,
        [session.tenant_id, sessionId]
      );
    }
    res.status(201).json({ requested: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao solicitar conta' });
  }
});

// GET /api/public/bill-request/:sessionId  — verifica se tem solicitação pendente
app.get('/api/public/bill-request/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  try {
    const result = await pool.query(
      `SELECT id, status, requested_at FROM bill_requests
       WHERE session_id = $1 ORDER BY requested_at DESC LIMIT 1`,
      [sessionId]
    );
    res.json(result.rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: 'Erro' });
  }
});

// GET /api/bill-requests?tenantId=xxx  — garçom vê todas as solicitações pendentes
app.get('/api/bill-requests', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    const result = await pool.query(
      `SELECT br.id, br.session_id, br.status, br.requested_at,
              t.code AS table_code, t.name AS table_name
       FROM bill_requests br
       JOIN table_sessions ts ON ts.id = br.session_id
       JOIN tables t ON t.id = ts.table_id
       WHERE br.tenant_id = $1 AND br.status = 'PENDING'
       ORDER BY br.requested_at ASC`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro' });
  }
});

// PATCH /api/bill-requests/:id/seen  — garçom marca como visto
app.patch('/api/bill-requests/:id/seen', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { seenBy } = req.body;
  try {
    await pool.query(
      `UPDATE bill_requests SET status = 'SEEN', seen_at = now(), seen_by = $1 WHERE id = $2`,
      [seenBy || null, id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro' });
  }
});

// GET /api/waiter/tables/:tenantId  — visão do garçom: mesas com sessão e pedidos
app.get('/api/waiter/tables/:tenantId', async (req, res) => {
  const { tenantId } = req.params;
  try {
    const result = await pool.query(
      `SELECT
         t.id, t.code, t.name, t.is_active,
         ts.id AS session_id, ts.status AS session_status, ts.opened_at,
         COUNT(DISTINCT o.id) FILTER (WHERE o.status IN ('NEW','PREPARING','READY')) AS active_orders,
         EXISTS (
           SELECT 1 FROM bill_requests br
           WHERE br.session_id = ts.id AND br.status = 'PENDING'
         ) AS bill_requested
       FROM tables t
       LEFT JOIN table_sessions ts ON ts.table_id = t.id AND ts.status = 'OPEN'
       LEFT JOIN orders o ON o.session_id = ts.id
       WHERE t.tenant_id = $1 AND t.is_active = TRUE
       GROUP BY t.id, t.code, t.name, t.is_active, ts.id, ts.status, ts.opened_at
       ORDER BY t.code`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar mesas' });
  }
});

// GET /api/waiter/session/:sessionId  — detalhes da sessão para o garçom
app.get('/api/waiter/session/:sessionId', async (req, res) => {
  const { sessionId } = req.params;
  try {
    const [sessionResult, ordersResult, billResult] = await Promise.all([
      pool.query(
        `SELECT ts.id, ts.opened_at, ts.status,
                t.code AS table_code, t.name AS table_name
         FROM table_sessions ts JOIN tables t ON t.id = ts.table_id
         WHERE ts.id = $1`, [sessionId]
      ),
      pool.query(
        `SELECT o.id, o.status, o.source, o.created_at,
                json_agg(
                  json_build_object(
                    'id', oi.id,
                    'product_id', oi.product_id,
                    'product_name', p.name,
                    'qty', oi.qty,
                    'unit_price_cents', oi.unit_price_cents,
                    'notes', oi.notes
                  ) ORDER BY oi.id
                ) AS items
         FROM orders o
         JOIN order_items oi ON oi.order_id = o.id
         JOIN products p ON p.id = oi.product_id
         WHERE o.session_id = $1
         GROUP BY o.id ORDER BY o.created_at DESC`, [sessionId]
      ),
      pool.query(
        `SELECT id, status FROM bill_requests WHERE session_id = $1 AND status = 'PENDING' LIMIT 1`,
        [sessionId]
      ),
    ]);
    if (!sessionResult.rows[0]) return res.status(404).json({ error: 'Sessão não encontrada' });
    res.json({
      session: sessionResult.rows[0],
      orders: ordersResult.rows,
      billRequest: billResult.rows[0] || null,
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro' });
  }
});

// POST /api/waiter/login — login do garçom (busca user por email/senha dentro do tenant)
app.post('/api/waiter/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });
  try {
    // Busca o usuário pelo email em qualquer tenant ativo
    const userResult = await pool.query(
      `SELECT u.id, u.name, u.role, u.tenant_id, u.password_hash,
              t.id AS tid, t.name AS tenant_name, t.slug
       FROM users u
       JOIN tenants t ON t.id = u.tenant_id
       WHERE u.email = $1 AND u.is_active = TRUE AND t.is_active = TRUE`,
      [email]
    );
    const user = userResult.rows[0];
    if (!user) return res.status(401).json({ error: 'Email ou senha inválidos' });

    // Verifica senha com bcrypt via função do banco
    const check = await pool.query(
      'SELECT auth_verify_password($1, $2) AS ok',
      [password, user.password_hash]
    );
    if (!check.rows[0].ok) return res.status(401).json({ error: 'Email ou senha inválidos' });

    const token = jwt.sign(
      { userId: user.id, role: user.role, tenantId: user.tenant_id },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    log('INFO', 'LOGIN_GARCOM', { email, nome: user.name, tenant: user.tenant_name });
    res.json({
      userId: user.id,
      userName: user.name,
      userRole: user.role,
      tenantId: user.tenant_id,
      tenantName: user.tenant_name,
      slug: user.slug,
      token,
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ─── KDS (Kitchen/Bar Display) ────────────────────────────────────────────────
// GET /api/kds/:tenantId/:sector — pedidos ativos filtrados por setor
app.get('/api/kds/:tenantId/:sector', async (req, res) => {
  const { tenantId, sector } = req.params;
  const sectorUpper = sector.toUpperCase();
  if (!['KITCHEN', 'BAR'].includes(sectorUpper)) {
    return res.status(400).json({ error: 'Setor inválido. Use KITCHEN ou BAR' });
  }
  try {
    const result = await pool.query(
      `SELECT
         o.id, o.status, o.source, o.created_at,
         COALESCE(t.code, 'BALCÃO') AS table_code,
         COALESCE(t.name, 'Pedido Balcão') AS table_name,
         EXTRACT(EPOCH FROM (now() - o.created_at))::int AS elapsed_seconds,
         json_agg(
           json_build_object(
             'id',             oi.id,
             'product_name',   p.name,
             'product_sector', p.sector,
             'qty',            oi.qty,
             'notes',          oi.notes
           ) ORDER BY oi.id
         ) AS items
       FROM orders o
       JOIN order_items oi    ON oi.order_id  = o.id
       JOIN products p        ON p.id         = oi.product_id
       LEFT JOIN table_sessions ts ON ts.id   = o.session_id
       LEFT JOIN tables t     ON t.id         = ts.table_id
       WHERE o.tenant_id = $1
         AND o.status IN ('NEW','PREPARING','READY')
         AND p.sector = $2
       GROUP BY o.id, t.code, t.name
       ORDER BY
         CASE o.source WHEN 'BALCAO' THEN 0 ELSE 1 END,
         CASE o.status WHEN 'NEW' THEN 0 WHEN 'PREPARING' THEN 1 ELSE 2 END,
         o.created_at ASC`,
      [tenantId, sectorUpper]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar pedidos KDS' });
  }
});

// ─── TENANT SETTINGS ──────────────────────────────────────────────────────────

// GET /api/tenant/:id — busca dados completos do tenant
app.get('/api/tenant/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT id, name, slug, email, cnpj, phone, address, city, state,
              zip_code, logo_url, description, is_active, kitchen_closed, created_at,
              brand_color, brand_color_secondary
       FROM tenants WHERE id = $1`,
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Empresa não encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar dados da empresa' });
  }
});

// PATCH /api/tenant/:id — atualiza dados do tenant
app.patch('/api/tenant/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, cnpj, phone, address, city, state, zip_code, logo_url, description, kitchen_closed, brand_color, brand_color_secondary } = req.body;
  try {
    const result = await pool.query(
      `UPDATE tenants SET
         name                  = COALESCE($1, name),
         email                 = COALESCE($2, email),
         cnpj                  = $3,
         phone                 = $4,
         address               = $5,
         city                  = $6,
         state                 = $7,
         zip_code              = $8,
         logo_url              = COALESCE($9, logo_url),
         description           = $10,
         kitchen_closed        = COALESCE($11, kitchen_closed),
         brand_color           = COALESCE($12, brand_color),
         brand_color_secondary = COALESCE($13, brand_color_secondary)
       WHERE id = $14
       RETURNING id, name, slug, email, cnpj, phone, address, city, state, zip_code,
                 logo_url, description, is_active, kitchen_closed, created_at,
                 brand_color, brand_color_secondary`,
      [name, email, cnpj || null, phone || null, address || null, city || null,
       state || null, zip_code || null, logo_url || null, description || null,
       kitchen_closed !== undefined ? kitchen_closed : null,
       brand_color || null, brand_color_secondary || null, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Empresa não encontrada' });
    log('INFO', 'CONFIGURACOES_ATUALIZADAS', { tenantId: id, nome: name, feito_por: req.user?.userId });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar dados da empresa' });
  }
});
app.patch('/api/tenant/:id/kitchen-toggle', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `UPDATE tenants SET kitchen_closed = NOT kitchen_closed WHERE id = $1
       RETURNING id, kitchen_closed`,
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Empresa não encontrada' });
    const estado = result.rows[0].kitchen_closed ? 'FECHADA' : 'ABERTA';
    log('WARN', 'COZINHA_TOGGLE', { tenantId: id, estado, feito_por: req.user?.userId });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao alterar estado da cozinha' });
  }
});

// PATCH /api/users/:id/password — troca senha com controle por role
// ADMIN pode trocar de qualquer um | MANAGER pode trocar garçom e a própria | WAITER só a própria
app.patch('/api/users/:id/password', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  const reqUser = req.user; // { userId, role, tenantId }

  if (!password || password.length < 4) {
    return res.status(400).json({ error: 'Senha deve ter ao menos 4 caracteres' });
  }

  try {
    // Busca o usuário alvo
    const targetRes = await pool.query('SELECT id, role, tenant_id FROM users WHERE id = $1', [id]);
    const target = targetRes.rows[0];
    if (!target) return res.status(404).json({ error: 'Usuário não encontrado' });

    // Verifica permissão
    const isSelf = reqUser.userId === id;
    const isAdmin = reqUser.role === 'ADMIN';
    const isManager = reqUser.role === 'MANAGER';
    const targetIsWaiter = ['WAITER', 'CASHIER', 'KITCHEN', 'BAR'].includes(target.role);

    if (!isSelf && !isAdmin && !(isManager && targetIsWaiter)) {
      return res.status(403).json({ error: 'Sem permissão para alterar a senha deste usuário' });
    }

    // Garante que manager não altera senha de outro manager ou admin
    if (isManager && !isSelf && !targetIsWaiter) {
      return res.status(403).json({ error: 'Gerentes só podem alterar senha de garçons' });
    }

    // USA bcrypt igual ao login — auth_hash_password() usa sistema diferente
    const hash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, id]);

    // Se for ADMIN, atualiza também tenants.password_hash (usado pelo tenant_login())
    if (target.role === 'ADMIN') {
      const pgHash = (await pool.query('SELECT auth_hash_password($1) AS h', [password])).rows[0].h;
      await pool.query('UPDATE tenants SET password_hash = $1 WHERE id = $2', [pgHash, target.tenant_id]);
    }

    log('WARN', 'TROCA_SENHA', {
      alvo: id,
      role_alvo: target.role,
      feito_por: reqUser.userId,
      role_feito: reqUser.role,
      propria: isSelf ? 'sim' : 'nao',
    });
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao alterar senha' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// SUPER ADMIN — autenticação e painel SaaS
// ════════════════════════════════════════════════════════════════════════════════

// Middleware simples de auth super admin (token em header)
function superAdminAuth(req, res, next) {
  const header = req.headers['authorization'] || req.headers['x-super-token'];
  const token = header?.startsWith('Bearer ') ? header.split(' ')[1] : header;
  if (!token) return res.status(401).json({ error: 'Token obrigatório' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload.superAdminId) return res.status(401).json({ error: 'Token inválido' });
    req.superAdminId = payload.superAdminId;
    req.superAdmin = { id: payload.superAdminId, email: payload.email };
    next();
  } catch { return res.status(401).json({ error: 'Token inválido ou expirado' }); }
}

function makeSuperToken(id, email) {
  return jwt.sign({ superAdminId: id, email }, JWT_SECRET, { expiresIn: '8h' });
}

// POST /api/super/login
app.post('/api/super/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });
  try {
    const result = await pool.query(
      'SELECT id, name, email, password_hash, is_active FROM super_admins WHERE email = $1',
      [email]
    );
    const admin = result.rows[0];
    if (!admin || !admin.is_active) return res.status(401).json({ error: 'Credenciais inválidas' });

    const ok = (await pool.query('SELECT auth_verify_password($1,$2) AS ok', [password, admin.password_hash])).rows[0].ok;
    if (!ok) return res.status(401).json({ error: 'Credenciais inválidas' });

    await pool.query('UPDATE super_admins SET last_login_at = now() WHERE id = $1', [admin.id]);
    log('WARN', 'LOGIN_SUPER_ADMIN', { email, adminId: admin.id });
    res.json({ id: admin.id, name: admin.name, email: admin.email, token: makeSuperToken(admin.id, admin.email) });
  } catch (err) { log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err); res.status(500).json({ error: 'Erro interno' }); }
});

// GET /api/super/dashboard — métricas gerais
app.get('/api/super/dashboard', superAdminAuth, async (req, res) => {
  try {
    const [counts, revenue, invoices, recentTenants] = await Promise.all([
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE is_active AND status = 'ACTIVE')   AS active,
          COUNT(*) FILTER (WHERE status = 'TRIAL')                  AS trial,
          COUNT(*) FILTER (WHERE status = 'SUSPENDED')              AS suspended,
          COUNT(*) FILTER (WHERE status = 'CANCELLED')              AS cancelled,
          COUNT(*)                                                    AS total
        FROM tenants`),
      pool.query(`
        SELECT
          COALESCE(SUM(amount_cents) FILTER (WHERE status='PAID' AND paid_at >= date_trunc('month', now())), 0) AS mrr,
          COALESCE(SUM(amount_cents) FILTER (WHERE status='PAID'), 0)                                           AS total_received,
          COALESCE(SUM(amount_cents) FILTER (WHERE status='PENDING'), 0)                                        AS pending,
          COALESCE(SUM(amount_cents) FILTER (WHERE status='OVERDUE'), 0)                                        AS overdue
        FROM invoices`),
      pool.query(`SELECT COUNT(*) FILTER (WHERE status='OVERDUE') AS overdue_count FROM invoices`),
      pool.query(`
        SELECT t.id, t.name, t.slug, t.status, t.created_at, p.name AS plan_name, p.price_cents
        FROM tenants t LEFT JOIN plans p ON p.id = t.plan_id
        ORDER BY t.created_at DESC LIMIT 5`),
    ]);
    res.json({
      tenants: counts.rows[0],
      revenue: revenue.rows[0],
      overdueCount: invoices.rows[0].overdue_count,
      recentTenants: recentTenants.rows,
    });
  } catch (err) { log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err); res.status(500).json({ error: 'Erro' }); }
});

// GET /api/super/tenants — lista todos os restaurantes
app.get('/api/super/tenants', superAdminAuth, async (req, res) => {
  const { search, status } = req.query;
  try {
    let q = `
      SELECT t.id, t.name, t.slug, t.email, t.phone, t.cnpj, t.status,
             t.contract_start, t.contract_end, t.trial_ends_at, t.notes,
             t.created_at, t.is_active,
             p.id AS plan_id, p.name AS plan_name, p.price_cents,
             COUNT(DISTINCT u.id) FILTER (WHERE u.is_active) AS user_count,
             COUNT(DISTINCT tb.id) FILTER (WHERE tb.is_active) AS table_count,
             COALESCE(SUM(i.amount_cents) FILTER (WHERE i.status = 'PAID'), 0) AS total_paid,
             MAX(i.due_date) FILTER (WHERE i.status = 'PENDING') AS next_due
      FROM tenants t
      LEFT JOIN plans p ON p.id = t.plan_id
      LEFT JOIN users u ON u.tenant_id = t.id
      LEFT JOIN tables tb ON tb.tenant_id = t.id
      LEFT JOIN invoices i ON i.tenant_id = t.id
      WHERE 1=1`;
    const params = [];
    if (search) { params.push(`%${search}%`); q += ` AND (t.name ILIKE $${params.length} OR t.email ILIKE $${params.length} OR t.slug ILIKE $${params.length})`; }
    if (status) { params.push(status); q += ` AND t.status = $${params.length}`; }
    q += ` GROUP BY t.id, p.id ORDER BY t.created_at DESC`;
    const result = await pool.query(q, params);
    res.json(result.rows);
  } catch (err) { log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err); res.status(500).json({ error: 'Erro' }); }
});

// POST /api/super/tenants — cria novo restaurante + admin
app.post('/api/super/tenants', superAdminAuth, async (req, res) => {
  const { name, slug, email, planId, adminName, adminEmail, adminPassword, notes, trialDays } = req.body;
  if (!name || !adminEmail || !adminPassword) {
    return res.status(400).json({ error: 'name, adminEmail e adminPassword são obrigatórios' });
  }
  // Auto-gera slug se não fornecido
  const finalSlug = slug || name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') + '-' + Date.now().toString(36);
  const finalEmail = email || adminEmail;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const status = trialDays ? 'TRIAL' : 'ACTIVE';
    const trialEnd = trialDays ? `now() + interval '${parseInt(trialDays)} days'` : null;

    const adminPasswordHash = await bcrypt.hash(adminPassword, 10);

    const tenantResult = await client.query(
      `INSERT INTO tenants (name, slug, email, password_hash, plan_id, status, notes, trial_ends_at, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, $7, ${trialEnd ? `now() + interval '${parseInt(trialDays)} days'` : 'NULL'}, TRUE)
       RETURNING *`,
      [name, finalSlug, finalEmail, adminPasswordHash, planId || null, status, notes || null]
    );
    const tenant = tenantResult.rows[0];

    await client.query(
      `INSERT INTO users (tenant_id, name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, 'ADMIN')`,
      [tenant.id, adminName || name, adminEmail, adminPasswordHash]
    );

    // Gera fatura inicial se tiver plano
    if (planId) {
      const plan = (await client.query('SELECT price_cents FROM plans WHERE id=$1', [planId])).rows[0];
      if (plan?.price_cents > 0) {
        await client.query(
          `INSERT INTO invoices (tenant_id, plan_id, amount_cents, status, due_date)
           VALUES ($1, $2, $3, 'PENDING', (now() + interval '30 days')::date)`,
          [tenant.id, planId, plan.price_cents]
        );
      }
    }

    await client.query('COMMIT');
    log('INFO', 'TENANT_CRIADO', { tenantId: tenant.id, nome: tenant.name, slug: tenant.slug, plano: planId });

    // Envia e-mail de boas-vindas com credenciais (não bloqueia a resposta)
    sendWelcomeEmail({
      tenantName:    name,
      adminEmail,
      adminPassword,
      slug:          finalSlug,
      trialDays:     trialDays || null,
    }).catch(e => log('WARN', 'EMAIL_BOAS_VINDAS_FALHOU', { msg: e?.message }));

    res.status(201).json(tenant);
  } catch (err) {
    await client.query('ROLLBACK');
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    if (err.code === '23505') return res.status(409).json({ error: 'Slug ou email já cadastrado' });
    res.status(500).json({ error: 'Erro ao criar restaurante' });
  } finally { client.release(); }
});

// PATCH /api/super/tenants/:id — edita restaurante (plano, status, notas)
app.patch('/api/super/tenants/:id', superAdminAuth, async (req, res) => {
  const { id } = req.params;
  const { name, email, planId, status, notes, contractEnd, isActive } = req.body;
  try {
    const result = await pool.query(
      `UPDATE tenants SET
        name           = COALESCE($1, name),
        email          = COALESCE($2, email),
        plan_id        = COALESCE($3, plan_id),
        status         = COALESCE($4, status),
        notes          = COALESCE($5, notes),
        contract_end   = COALESCE($6::timestamptz, contract_end),
        is_active      = COALESCE($7, is_active)
       WHERE id = $8 RETURNING *`,
      [name, email, planId, status, notes, contractEnd || null, isActive, id]
    );
    res.json(result.rows[0]);
  } catch (err) { log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err); res.status(500).json({ error: 'Erro' }); }
});

// GET /api/super/tenants/:id/invoices — faturas de um restaurante
app.get('/api/super/tenants/:id/invoices', superAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT i.*, p.name AS plan_name FROM invoices i
       LEFT JOIN plans p ON p.id = i.plan_id
       WHERE i.tenant_id = $1 ORDER BY i.due_date DESC`,
      [id]
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Erro' }); }
});

// POST /api/super/tenants/:id/invoices — cria fatura manual
app.post('/api/super/tenants/:id/invoices', superAdminAuth, async (req, res) => {
  const { id } = req.params;
  const { amountCents, dueDate, notes, planId } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO invoices (tenant_id, plan_id, amount_cents, status, due_date, notes)
       VALUES ($1,$2,$3,'PENDING',$4,$5) RETURNING *`,
      [id, planId || null, amountCents, dueDate, notes || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Erro' }); }
});

// PATCH /api/super/invoices/:id — marca fatura como paga/cancelada
app.patch('/api/super/invoices/:id', superAdminAuth, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const result = await pool.query(
      `UPDATE invoices SET status=$1, paid_at = CASE WHEN $1='PAID' THEN now() ELSE paid_at END
       WHERE id=$2 RETURNING *`,
      [status, id]
    );
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Erro' }); }
});

// GET /api/super/plans — lista planos
app.get('/api/super/plans', superAdminAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM plans WHERE is_active=TRUE ORDER BY price_cents');
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Erro' }); }
});

// GET /api/super/invoices — todas as faturas com filtros
app.get('/api/super/invoices', superAdminAuth, async (req, res) => {
  const { status } = req.query;
  try {
    const VALID_STATUSES = ['PENDING','PAID','OVERDUE','CANCELLED'];
    const safeStatus = status && VALID_STATUSES.includes(status.toUpperCase()) ? status.toUpperCase() : null;
    const result = await pool.query(
      `SELECT i.*, t.name AS tenant_name, p.name AS plan_name
       FROM invoices i
       JOIN tenants t ON t.id = i.tenant_id
       LEFT JOIN plans p ON p.id = i.plan_id
       ${safeStatus ? 'WHERE i.status = $1' : ''}
       ORDER BY i.due_date DESC LIMIT 100`,
      safeStatus ? [safeStatus] : []
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Erro' }); }
});

// ════════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════════
// API TOKENS — gerenciados apenas pelo Super Admin
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/super/api-tokens?tenantId= — lista tokens de um restaurante
app.get('/api/super/api-tokens', superAdminAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatorio' });
  try {
    const result = await pool.query(
      `SELECT id, name, created_by, is_active, expires_at, last_used_at, created_at,
              LEFT(token_hash, 8) AS token_prefix
       FROM api_tokens WHERE tenant_id = $1 ORDER BY created_at DESC`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao listar tokens' });
  }
});

// POST /api/super/api-tokens — cria novo token para um restaurante
app.post('/api/super/api-tokens', superAdminAuth, async (req, res) => {
  const { tenantId, name, expiresInDays } = req.body;
  if (!tenantId || !name) return res.status(400).json({ error: 'tenantId e name sao obrigatorios' });

  // Gera token aleatório: prefixo legível + 32 bytes hex
  const rawToken = 'msy_' + crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);

  const expiresAt = expiresInDays
    ? new Date(Date.now() + parseInt(expiresInDays) * 86400000).toISOString()
    : null;

  try {
    const result = await pool.query(
      `INSERT INTO api_tokens (tenant_id, name, token_hash, created_by, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, created_by, is_active, expires_at, created_at`,
      [tenantId, name, tokenHash, req.superAdmin?.email || 'super_admin', expiresAt]
    );
    log('WARN', 'API_TOKEN_CRIADO', { tenantId, nome: name, expiresAt });
    // Retorna o token RAW apenas uma vez — não armazenamos ele
    res.status(201).json({ ...result.rows[0], raw_token: rawToken });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao criar token' });
  }
});

// DELETE /api/super/api-tokens/:id — revoga token
app.delete('/api/super/api-tokens/:id', superAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE api_tokens SET is_active = FALSE WHERE id = $1', [id]);
    log('WARN', 'API_TOKEN_REVOGADO', { tokenId: id });
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao revogar token' });
  }
});

// DELETE /api/super/api-tokens/:id/permanent — exclui permanentemente
app.delete('/api/super/api-tokens/:id/permanent', superAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM api_tokens WHERE id = $1', [id]);
    log('WARN', 'API_TOKEN_EXCLUIDO', { tokenId: id });
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao excluir token' });
  }
});

// GET /api/developer/info — info pública do tenant para página de docs (requer auth normal)
app.get('/api/developer/info', requireAuth, async (req, res) => {
  const tenantId = req.user?.tenantId;
  try {
    const t = await pool.query(
      'SELECT id, name, slug FROM tenants WHERE id = $1', [tenantId]
    );
    const tokens = await pool.query(
      `SELECT id, name, is_active, last_used_at, created_at, expires_at
       FROM api_tokens WHERE tenant_id = $1 AND is_active = TRUE ORDER BY created_at DESC`,
      [tenantId]
    );
    res.json({ tenant: t.rows[0], tokens: tokens.rows });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar info' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// RELATÓRIOS
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/reports/overview?tenantId=&from=&to=
app.get('/api/reports/overview', requireAuth, async (req, res) => {
  const { tenantId, from, to } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  const dateFrom = from || new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().slice(0,10);
  const dateTo   = to   || new Date().toISOString().slice(0,10);
  try {
    const [revenue, orders, sessions, topProducts, byMethod, byDay, team] = await Promise.all([

      // Faturamento total no período
      pool.query(`
        SELECT
          COALESCE(SUM(p.amount_cents), 0)          AS total_cents,
          COALESCE(AVG(p.amount_cents), 0)          AS avg_ticket_cents,
          COUNT(DISTINCT p.id)                       AS payment_count,
          COUNT(DISTINCT p.session_id)               AS sessions_count
        FROM payments p
        WHERE p.tenant_id = $1
          AND DATE(p.created_at) BETWEEN $2 AND $3`,
        [tenantId, dateFrom, dateTo]
      ),

      // Pedidos no período
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE o.status != 'CANCELLED')  AS total_orders,
          COUNT(*) FILTER (WHERE o.status = 'CANCELLED')   AS cancelled_orders,
          COUNT(*) FILTER (WHERE o.source = 'CUSTOMER')    AS customer_orders,
          COUNT(*) FILTER (WHERE o.source = 'WAITER')      AS waiter_orders,
          COALESCE(SUM(oi.qty * oi.unit_price_cents) FILTER (WHERE o.status != 'CANCELLED'), 0) AS items_total_cents
        FROM orders o
        LEFT JOIN order_items oi ON oi.order_id = o.id
        WHERE o.tenant_id = $1
          AND DATE(o.created_at) BETWEEN $2 AND $3`,
        [tenantId, dateFrom, dateTo]
      ),

      // Mesas e tempo médio de atendimento
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'CLOSED')   AS closed_sessions,
          COUNT(*) FILTER (WHERE status = 'OPEN')     AS open_sessions,
          ROUND(AVG(EXTRACT(EPOCH FROM (closed_at - opened_at))/60) FILTER (WHERE status = 'CLOSED'), 1) AS avg_duration_min
        FROM table_sessions
        WHERE tenant_id = $1
          AND DATE(opened_at) BETWEEN $2 AND $3`,
        [tenantId, dateFrom, dateTo]
      ),

      // Top 10 produtos mais vendidos
      pool.query(`
        SELECT
          p.name,
          p.sector,
          mc.name AS category,
          SUM(oi.qty)                            AS total_qty,
          SUM(oi.qty * oi.unit_price_cents)      AS revenue_cents
        FROM order_items oi
        JOIN products p   ON p.id  = oi.product_id
        JOIN orders o     ON o.id  = oi.order_id
        LEFT JOIN menu_categories mc ON mc.id = p.category_id
        WHERE oi.tenant_id = $1
          AND DATE(o.created_at) BETWEEN $2 AND $3
          AND o.status != 'CANCELLED'
        GROUP BY p.id, p.name, p.sector, mc.name
        ORDER BY total_qty DESC
        LIMIT 10`,
        [tenantId, dateFrom, dateTo]
      ),

      // Faturamento por forma de pagamento
      pool.query(`
        SELECT
          method,
          COUNT(*)          AS count,
          SUM(amount_cents) AS total_cents
        FROM payments
        WHERE tenant_id = $1
          AND DATE(created_at) BETWEEN $2 AND $3
        GROUP BY method
        ORDER BY total_cents DESC`,
        [tenantId, dateFrom, dateTo]
      ),

      // Faturamento por dia (para o gráfico)
      pool.query(`
        SELECT
          TO_CHAR(DATE(p.created_at), 'YYYY-MM-DD') AS day,
          COALESCE(SUM(p.amount_cents), 0) AS revenue_cents,
          COUNT(DISTINCT p.id)       AS payment_count
        FROM payments p
        WHERE p.tenant_id = $1
          AND DATE(p.created_at) BETWEEN $2 AND $3
        GROUP BY DATE(p.created_at)
        ORDER BY day ASC`,
        [tenantId, dateFrom, dateTo]
      ),

      // Equipe
      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE is_active)          AS active_count,
          COUNT(*) FILTER (WHERE NOT is_active)      AS inactive_count,
          COUNT(*) FILTER (WHERE role = 'ADMIN')     AS admins,
          COUNT(*) FILTER (WHERE role = 'WAITER')    AS waiters,
          COUNT(*) FILTER (WHERE role = 'CASHIER')   AS cashiers,
          COUNT(*) FILTER (WHERE role = 'KITCHEN')   AS kitchen,
          COUNT(*) FILTER (WHERE role = 'BAR')       AS bar
        FROM users
        WHERE tenant_id = $1`,
        [tenantId]
      ),
    ]);

    res.json({
      period: { from: dateFrom, to: dateTo },
      revenue:     revenue.rows[0],
      orders:      orders.rows[0],
      sessions:    sessions.rows[0],
      topProducts: topProducts.rows,
      byMethod:    byMethod.rows,
      byDay:       byDay.rows,
      team:        team.rows[0],
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao gerar relatório' });
  }
});

// GET /api/reports/history?tenantId=&from=&to=&page=&limit=
app.get('/api/reports/history', requireAuth, async (req, res) => {
  const { tenantId, from, to, page = '1', limit = '20' } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const dateFrom = from || new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().slice(0,10);
  const dateTo   = to   || new Date().toISOString().slice(0,10);
  try {
    const result = await pool.query(`
      SELECT
        ts.id, ts.opened_at, ts.closed_at, ts.status,
        t.code AS table_code, t.name AS table_name,
        COUNT(DISTINCT o.id) FILTER (WHERE o.status != 'CANCELLED') AS order_count,
        COALESCE(SUM(oi.qty * oi.unit_price_cents) FILTER (WHERE o.status != 'CANCELLED'), 0) AS subtotal_cents,
        COALESCE(SUM(p.amount_cents), 0) AS paid_cents,
        MAX(p.method) AS payment_method,
        ROUND(EXTRACT(EPOCH FROM (ts.closed_at - ts.opened_at))/60, 0) AS duration_min,
        u.name AS closed_by_name
      FROM table_sessions ts
      JOIN tables t ON t.id = ts.table_id
      LEFT JOIN orders o ON o.session_id = ts.id
      LEFT JOIN order_items oi ON oi.order_id = o.id
      LEFT JOIN payments p ON p.session_id = ts.id
      LEFT JOIN users u ON u.id = ts.closed_by
      WHERE ts.tenant_id = $1
        AND DATE(ts.opened_at) BETWEEN $2 AND $3
        AND ts.status = 'CLOSED'
      GROUP BY ts.id, t.code, t.name, u.name
      ORDER BY ts.closed_at DESC
      LIMIT $4 OFFSET $5`,
      [tenantId, dateFrom, dateTo, parseInt(limit), offset]
    );
    res.json(result.rows);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao buscar histórico' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// UPLOAD DE FOTO DE PRODUTO
// ════════════════════════════════════════════════════════════════════════════════

// POST /api/products/:id/image
app.post('/api/products/:id/image', requireAuth, uploadProduct.single('image'), async (req, res) => {
  const { id } = req.params;
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

  try {
    // Remove imagem antiga do Cloudinary se existir
    const old = await pool.query('SELECT image_url FROM products WHERE id = $1', [id]);
    const oldUrl = old.rows[0]?.image_url;
    if (oldUrl && oldUrl.includes('cloudinary.com')) {
      const publicId = oldUrl.split('/').slice(-2).join('/').replace(/\.[^.]+$/, '');
      await cloudinary.uploader.destroy(publicId).catch(() => {});
    } else if (oldUrl?.startsWith('/uploads/')) {
      const oldPath = path.join(UPLOADS_DIR, path.basename(oldUrl));
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    // Upload para Cloudinary
    const result = await uploadToCloudinary(req.file.buffer, 'mesafay/products', `product-${id}`);
    const imageUrl = result.secure_url;

    await pool.query('UPDATE products SET image_url = $1 WHERE id = $2', [imageUrl, id]);
    log('INFO', 'IMAGEM_PRODUTO', { produtoId: id, url: imageUrl });
    res.json({ image_url: imageUrl });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao salvar imagem: ' + err.message });
  }
});

// DELETE /api/products/:id/image
app.delete('/api/products/:id/image', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT image_url FROM products WHERE id = $1', [id]);
    const url = result.rows[0]?.image_url;
    if (url?.startsWith('/uploads/')) {
      const filePath = path.join(UPLOADS_DIR, path.basename(url));
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    await pool.query('UPDATE products SET image_url = NULL WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao remover imagem' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// IMPORTAÇÃO CSV DE PRODUTOS
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/products/csv-template  — baixar modelo CSV
app.get('/api/products/csv-template', requireAuth, (req, res) => {
  const csv = [
    'nome,descricao,preco,categoria,setor,imagem_url',
    'X-Burguer Clássico,Pão brioche + blend 180g + queijo + alface + tomate,32.90,Lanches,KITCHEN,',
    'Batata Frita Crocante,Porção 300g com molho especial da casa,18.50,Acompanhamentos,KITCHEN,',
    'Coca-Cola 350ml,Lata gelada,8.00,Bebidas,BAR,',
    'Suco de Laranja Natural,500ml feito na hora,12.00,Bebidas,BAR,',
    'Brownie com Sorvete,Brownie quentinho com sorvete de creme,19.90,Sobremesas,KITCHEN,',
  ].join('\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="modelo-produtos.csv"');
  res.send('\uFEFF' + csv); // BOM para Excel reconhecer UTF-8
});

// POST /api/products/csv-import  — importar CSV
app.post('/api/products/csv-import', requireAuth, uploadCSV.single('csv'), async (req, res) => {
  const { tenantId } = req.body;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

  const { limits, planName } = await getPlanLimits(tenantId);
  if (!limits.csvImport) {
    return res.status(403).json({
      error: `Importação CSV não está disponível no plano ${planName || 'atual'}. Faça upgrade para o plano Pro ou Premium.`,
      code: 'PLAN_LIMIT_CSV',
    });
  }

  try {
    const text = req.file.buffer.toString('utf-8').replace(/^\uFEFF/, ''); // remove BOM
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 2) return res.status(400).json({ error: 'CSV vazio ou sem dados' });

    const header = lines[0].toLowerCase().split(',').map(h => h.trim());
    const colIdx = {
      nome:       header.indexOf('nome'),
      descricao:  header.indexOf('descricao'),
      preco:      header.indexOf('preco'),
      categoria:  header.indexOf('categoria'),
      setor:      header.indexOf('setor'),
      imagem_url: header.indexOf('imagem_url'),
    };

    if (colIdx.nome === -1 || colIdx.preco === -1 || colIdx.setor === -1) {
      return res.status(400).json({ error: 'CSV precisa ter as colunas: nome, preco, setor' });
    }

    // Busca categorias existentes do tenant
    const catsResult = await pool.query(
      'SELECT id, name FROM menu_categories WHERE tenant_id = $1 AND is_active = TRUE',
      [tenantId]
    );
    const catsMap = {};
    catsResult.rows.forEach(c => { catsMap[c.name.toLowerCase().trim()] = c.id; });

    const errors = [];
    const toInsert = [];

    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].split(',').map(c => c.trim().replace(/^"|"$/g, ''));
      const nome = cols[colIdx.nome] || '';
      const precoStr = (cols[colIdx.preco] || '0').replace('R$', '').replace(/\s/g, '').replace(',', '.').trim();
      const preco = parseFloat(precoStr);
      const setor = (cols[colIdx.setor] || '').toUpperCase().trim();
      const categoria = colIdx.categoria >= 0 ? (cols[colIdx.categoria] || '').trim() : '';
      const descricao = colIdx.descricao >= 0 ? (cols[colIdx.descricao] || '') : '';
      const imagemUrl = colIdx.imagem_url >= 0 ? (cols[colIdx.imagem_url] || '') : '';

      if (!nome) { errors.push(`Linha ${i+1}: nome vazio`); continue; }
      if (isNaN(preco) || preco < 0) { errors.push(`Linha ${i+1}: preço inválido "${cols[colIdx.preco]}"`); continue; }
      if (!['KITCHEN','BAR'].includes(setor)) { errors.push(`Linha ${i+1}: setor deve ser KITCHEN ou BAR`); continue; }

      // Cria categoria se não existir
      let categoryId = null;
      if (categoria) {
        const key = categoria.toLowerCase();
        if (catsMap[key]) {
          categoryId = catsMap[key];
        } else {
          const newCat = await pool.query(
            'INSERT INTO menu_categories (tenant_id, name, sort_order) VALUES ($1, $2, 0) RETURNING id',
            [tenantId, categoria]
          );
          categoryId = newCat.rows[0].id;
          catsMap[key] = categoryId;
        }
      }

      toInsert.push({ nome, descricao, price_cents: Math.round(preco * 100), setor, categoryId, imagemUrl });
    }

    // Insere todos
    const inserted = [];
    for (const p of toInsert) {
      const r = await pool.query(
        `INSERT INTO products (tenant_id, category_id, name, description, price_cents, sector, image_url, sort_order)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0) RETURNING *`,
        [tenantId, p.categoryId, p.nome, p.descricao || null, p.price_cents, p.setor, p.imagemUrl || null]
      );
      inserted.push(r.rows[0]);
    }

    log('INFO', 'CSV_IMPORTADO', { tenantId, importados: inserted.length, erros: errors.length });
    res.json({
      success: true,
      imported: inserted.length,
      errors: errors.length,
      errorDetails: errors,
      products: inserted,
    });
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: 'Erro ao importar CSV: ' + err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// RELATÓRIOS MENSAIS
// ════════════════════════════════════════════════════════════════════════════════

async function generateMonthlyReport(tenantId, year, month) {
  const start = new Date(year, month - 1, 1);
  const end   = new Date(year, month, 1);

  // Receita por método de pagamento
  const revenueRes = await pool.query(`
    SELECT
      COALESCE(SUM(amount_cents), 0)                                              AS total,
      COALESCE(SUM(CASE WHEN method = 'CASH'  THEN amount_cents ELSE 0 END), 0)  AS cash,
      COALESCE(SUM(CASE WHEN method = 'PIX'   THEN amount_cents ELSE 0 END), 0)  AS pix,
      COALESCE(SUM(CASE WHEN method = 'CARD'  THEN amount_cents ELSE 0 END), 0)  AS card,
      COALESCE(SUM(CASE WHEN method = 'OTHER' THEN amount_cents ELSE 0 END), 0)  AS other,
      COUNT(*)                                                                     AS payment_count
    FROM payments
    WHERE tenant_id = $1
      AND created_at >= $2 AND created_at < $3
  `, [tenantId, start, end]);

  // Total de sessões fechadas
  const sessionsRes = await pool.query(`
    SELECT COUNT(*) AS total FROM table_sessions
    WHERE tenant_id = $1 AND status = 'CLOSED' AND closed_at >= $2 AND closed_at < $3
  `, [tenantId, start, end]);

  // Total de pedidos
  const ordersRes = await pool.query(`
    SELECT COUNT(*) AS total FROM orders o
    JOIN table_sessions ts ON ts.id = o.session_id
    WHERE ts.tenant_id = $1 AND o.created_at >= $2 AND o.created_at < $3
      AND o.status != 'CANCELLED'
  `, [tenantId, start, end]);

  // Top 10 produtos
  const topRes = await pool.query(`
    SELECT p.name, SUM(oi.qty) AS qty, SUM(oi.qty * oi.unit_price_cents) AS revenue
    FROM order_items oi
    JOIN orders o ON o.id = oi.order_id
    JOIN products p ON p.id = oi.product_id
    JOIN table_sessions ts ON ts.id = o.session_id
    WHERE ts.tenant_id = $1 AND o.created_at >= $2 AND o.created_at < $3
      AND o.status != 'CANCELLED'
    GROUP BY p.name ORDER BY qty DESC LIMIT 10
  `, [tenantId, start, end]);

  // Receita diária
  const dailyRes = await pool.query(`
    SELECT DATE(created_at) AS day, COALESCE(SUM(amount_cents), 0) AS revenue
    FROM payments
    WHERE tenant_id = $1
      AND created_at >= $2 AND created_at < $3
    GROUP BY DATE(created_at) ORDER BY day
  `, [tenantId, start, end]);

  // Mês anterior para comparativo
  const prevStart = new Date(year, month - 2, 1);
  const prevEnd   = new Date(year, month - 1, 1);
  const prevRes   = await pool.query(`
    SELECT COALESCE(SUM(amount_cents), 0) AS total
    FROM payments
    WHERE tenant_id = $1
      AND created_at >= $2 AND created_at < $3
  `, [tenantId, prevStart, prevEnd]);

  const total    = parseInt(revenueRes.rows[0].total);
  const prevTotal= parseInt(prevRes.rows[0].total);
  const sessions = parseInt(sessionsRes.rows[0].total);
  const growth   = prevTotal > 0 ? parseFloat(((total - prevTotal) / prevTotal * 100).toFixed(2)) : 0;
  const avgTicket= sessions > 0 ? Math.round(total / sessions) : 0;

  // Upsert relatório
  await pool.query(`
    INSERT INTO monthly_reports (
      tenant_id, year, month,
      total_revenue_cents, total_orders, total_sessions, avg_ticket_cents,
      cash_revenue_cents, pix_revenue_cents, card_revenue_cents, other_revenue_cents,
      prev_month_revenue_cents, revenue_growth_pct,
      top_products, daily_revenue, generated_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW())
    ON CONFLICT (tenant_id, year, month) DO UPDATE SET
      total_revenue_cents = EXCLUDED.total_revenue_cents,
      total_orders = EXCLUDED.total_orders,
      total_sessions = EXCLUDED.total_sessions,
      avg_ticket_cents = EXCLUDED.avg_ticket_cents,
      cash_revenue_cents = EXCLUDED.cash_revenue_cents,
      pix_revenue_cents = EXCLUDED.pix_revenue_cents,
      card_revenue_cents = EXCLUDED.card_revenue_cents,
      other_revenue_cents = EXCLUDED.other_revenue_cents,
      prev_month_revenue_cents = EXCLUDED.prev_month_revenue_cents,
      revenue_growth_pct = EXCLUDED.revenue_growth_pct,
      top_products = EXCLUDED.top_products,
      daily_revenue = EXCLUDED.daily_revenue,
      generated_at = NOW()
  `, [
    tenantId, year, month,
    total,
    parseInt(ordersRes.rows[0].total),
    sessions,
    avgTicket,
    parseInt(revenueRes.rows[0].cash),
    parseInt(revenueRes.rows[0].pix),
    parseInt(revenueRes.rows[0].card),
    parseInt(revenueRes.rows[0].other),
    prevTotal,
    growth,
    JSON.stringify(topRes.rows),
    JSON.stringify(dailyRes.rows),
  ]);

  return { tenantId, year, month, total };
}

// Cron: todo dia 1° do mês às 00:05 gera relatório do mês anterior para todos os tenants
cron.schedule('5 0 1 * *', async () => {
  const now   = new Date();
  const year  = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();
  const month = now.getMonth() === 0 ? 12 : now.getMonth();
  log('INFO', 'CRON_RELATORIO_MENSAL_INICIO', { ano: year, mes: month });
  try {
    const tenants = await pool.query("SELECT id FROM tenants WHERE is_active = TRUE");
    for (const t of tenants.rows) {
      await generateMonthlyReport(t.id, year, month);
    }
    log('INFO', 'CRON_RELATORIO_MENSAL_FIM', { ano: year, mes: month, tenants: tenants.rows.length });
  } catch (err) {
    log('ERROR', 'CRON_RELATORIO_MENSAL_ERRO', { erro: err.message });
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
  }
});

// DELETE /api/monthly-reports/:id
app.delete('/api/monthly-reports/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM monthly_reports WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/monthly-reports?tenantId= — listar relatórios do tenant
app.get('/api/monthly-reports', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    const result = await pool.query(
      'SELECT * FROM monthly_reports WHERE tenant_id = $1 ORDER BY year DESC, month DESC',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/monthly-reports/:year/:month?tenantId= — relatório específico
app.get('/api/monthly-reports/:year/:month', requireAuth, async (req, res) => {
  const { year, month } = req.params;
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    const result = await pool.query(
      'SELECT * FROM monthly_reports WHERE tenant_id=$1 AND year=$2 AND month=$3',
      [tenantId, year, month]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Relatório não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/monthly-reports/generate — gera manualmente (admin pode forçar)
app.post('/api/monthly-reports/generate', requireAuth, async (req, res) => {
  const { tenantId, year, month } = req.body;
  if (!tenantId || !year || !month) return res.status(400).json({ error: 'tenantId, year e month obrigatórios' });

  const { limits, planName } = await getPlanLimits(tenantId);
  if (!limits.monthlyReports) {
    return res.status(403).json({
      error: `Relatórios mensais não estão disponíveis no plano ${planName || 'atual'}. Faça upgrade para o plano Pro ou Premium.`,
      code: 'PLAN_LIMIT_MONTHLY_REPORTS',
    });
  }

  try {
    log('INFO', 'RELATORIO_MENSAL_GERADO', { tenantId, ano: year, mes: month, feito_por: req.user?.userId });
    const result = await generateMonthlyReport(tenantId, parseInt(year), parseInt(month));
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// CAIXA (CASH REGISTER)
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/cash-register/current?tenantId= — caixa aberto atual
app.get('/api/cash-register/current', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    const result = await pool.query(
      `SELECT cr.*, 
        COALESCE((SELECT SUM(amount_cents) FROM cash_sangrias WHERE cash_register_id = cr.id), 0) AS total_sangrias_cents,
        COALESCE((SELECT json_agg(s ORDER BY s.created_at) FROM cash_sangrias s WHERE s.cash_register_id = cr.id), '[]') AS sangrias
       FROM cash_registers cr
       WHERE cr.tenant_id = $1 AND cr.status = 'OPEN'
       ORDER BY cr.opened_at DESC LIMIT 1`,
      [tenantId]
    );
    const reg = result.rows[0];
    if (!reg) return res.json(null);

    // Calcula totais em tempo real desde a abertura do caixa
    const totals = await pool.query(`
      SELECT
        COALESCE(SUM(amount_cents), 0) AS total,
        COALESCE(SUM(CASE WHEN method='CASH'  THEN amount_cents ELSE 0 END), 0) AS cash,
        COALESCE(SUM(CASE WHEN method='PIX'   THEN amount_cents ELSE 0 END), 0) AS pix,
        COALESCE(SUM(CASE WHEN method='CARD'  THEN amount_cents ELSE 0 END), 0) AS card,
        COALESCE(SUM(CASE WHEN method='OTHER' THEN amount_cents ELSE 0 END), 0) AS other
      FROM payments
      WHERE tenant_id=$1 AND created_at >= $2
    `, [tenantId, reg.opened_at]);

    const t = totals.rows[0];
    res.json({
      ...reg,
      total_revenue_cents:  parseInt(t.total),
      total_cash_in_cents:  parseInt(t.cash),
      total_pix_cents:      parseInt(t.pix),
      total_card_cents:     parseInt(t.card),
      total_other_cents:    parseInt(t.other),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/cash-register/history?tenantId= — histórico de caixas fechados
app.get('/api/cash-register/history', requireAuth, async (req, res) => {
  const { tenantId, page = 1, limit = 20 } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  const offset = (parseInt(page) - 1) * parseInt(limit);
  try {
    const result = await pool.query(
      `SELECT cr.*,
        COALESCE((SELECT json_agg(s ORDER BY s.created_at) FROM cash_sangrias s WHERE s.cash_register_id = cr.id), '[]') AS sangrias
       FROM cash_registers cr
       WHERE cr.tenant_id = $1
       ORDER BY cr.opened_at DESC
       LIMIT $2 OFFSET $3`,
      [tenantId, limit, offset]
    );
    const total = await pool.query('SELECT COUNT(*) FROM cash_registers WHERE tenant_id=$1', [tenantId]);
    res.json({ registers: result.rows, total: parseInt(total.rows[0].count), page: parseInt(page) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/cash-register/:id — detalhes de um caixa + todas as transações
app.get('/api/cash-register/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const regRes = await pool.query(
      `SELECT cr.*,
        COALESCE((SELECT json_agg(s ORDER BY s.created_at) FROM cash_sangrias s WHERE s.cash_register_id = cr.id), '[]') AS sangrias
       FROM cash_registers cr WHERE cr.id = $1`,
      [id]
    );
    if (!regRes.rows[0]) return res.status(404).json({ error: 'Caixa não encontrado' });
    const reg = regRes.rows[0];

    // Busca todos os pagamentos do período do caixa
    const closeTime = reg.closed_at || new Date();
    const paymentsRes = await pool.query(
      `SELECT p.*, ts.table_number, u.name AS operator_name
       FROM payments p
       JOIN table_sessions ts ON ts.id = p.session_id
       LEFT JOIN users u ON u.id = p.operator_id
       WHERE ts.tenant_id = $1 AND p.paid_at >= $2 AND p.paid_at <= $3
       ORDER BY p.paid_at ASC`,
      [reg.tenant_id, reg.opened_at, closeTime]
    );

    res.json({ ...reg, payments: paymentsRes.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/cash-register/open — abrir caixa
app.post('/api/cash-register/open', requireAuth, async (req, res) => {
  const { tenantId, operatorId, operatorName, openingBalance, notes } = req.body;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    // Verifica se já tem caixa aberto
    const existing = await pool.query(
      "SELECT id FROM cash_registers WHERE tenant_id=$1 AND status='OPEN'", [tenantId]
    );
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Já existe um caixa aberto' });

    const result = await pool.query(
      `INSERT INTO cash_registers (tenant_id, operator_id, operator_name, opening_balance_cents, opening_notes)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [tenantId, operatorId || null, operatorName || null, Math.round((parseFloat(openingBalance) || 0) * 100), notes || null]
    );
    log('INFO', 'CAIXA_ABERTO', { caixaId: result.rows[0].id, operador: operatorName, troco: openingBalance, tenantId });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/cash-register/:id/close — fechar caixa
app.post('/api/cash-register/:id/close', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { closingBalance, notes } = req.body;
  try {
    const regRes = await pool.query("SELECT * FROM cash_registers WHERE id=$1 AND status='OPEN'", [id]);
    if (!regRes.rows[0]) return res.status(404).json({ error: 'Caixa aberto não encontrado' });
    const reg = regRes.rows[0];

    // Calcula totais de pagamentos desde abertura usando tabela payments
    const totals = await pool.query(`
      SELECT
        COALESCE(SUM(amount_cents), 0) AS total,
        COALESCE(SUM(CASE WHEN method='CASH'  THEN amount_cents ELSE 0 END), 0) AS cash,
        COALESCE(SUM(CASE WHEN method='PIX'   THEN amount_cents ELSE 0 END), 0) AS pix,
        COALESCE(SUM(CASE WHEN method='CARD'  THEN amount_cents ELSE 0 END), 0) AS card,
        COALESCE(SUM(CASE WHEN method='OTHER' THEN amount_cents ELSE 0 END), 0) AS other
      FROM payments
      WHERE tenant_id=$1 AND created_at >= $2
    `, [reg.tenant_id, reg.opened_at]);

    const sangrias = await pool.query(
      'SELECT COALESCE(SUM(amount_cents),0) AS total FROM cash_sangrias WHERE cash_register_id=$1', [id]
    );

    const totalCash    = parseInt(totals.rows[0].cash);
    const totalSangria = parseInt(sangrias.rows[0].total);
    // Saldo esperado = troco inicial + entradas em dinheiro - sangrias
    const expectedBalance = reg.opening_balance_cents + totalCash - totalSangria;
    const closingCents    = Math.round((parseFloat(closingBalance) || 0) * 100);
    const difference      = closingCents - expectedBalance;

    const result = await pool.query(`
      UPDATE cash_registers SET
        status='CLOSED', closed_at=NOW(),
        closing_balance_cents=$1, expected_balance_cents=$2, difference_cents=$3,
        closing_notes=$4,
        total_cash_in_cents=$5, total_pix_cents=$6, total_card_cents=$7, total_other_cents=$8,
        total_sangria_cents=$9, total_revenue_cents=$10
      WHERE id=$11 RETURNING *
    `, [
      closingCents, expectedBalance, difference, notes || null,
      totalCash,
      parseInt(totals.rows[0].pix),
      parseInt(totals.rows[0].card),
      parseInt(totals.rows[0].other),
      totalSangria,
      parseInt(totals.rows[0].total),
      id
    ]);
    const r = result.rows[0];
    log('INFO', 'CAIXA_FECHADO', {
      caixaId: id,
      faturamento: (r.total_revenue_cents / 100).toFixed(2),
      dinheiro:    (r.total_cash_in_cents / 100).toFixed(2),
      pix:         (r.total_pix_cents / 100).toFixed(2),
      cartao:      (r.total_card_cents / 100).toFixed(2),
      sangrias:    (r.total_sangria_cents / 100).toFixed(2),
      diferenca:   (r.difference_cents / 100).toFixed(2),
    });
    res.json(r);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/cash-register/:id/sangria — registrar retirada
app.post('/api/cash-register/:id/sangria', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenantId, operatorId, operatorName, amount, reason } = req.body;
  if (!amount || parseFloat(amount) <= 0) return res.status(400).json({ error: 'Valor inválido' });
  try {
    const regRes = await pool.query("SELECT id FROM cash_registers WHERE id=$1 AND status='OPEN'", [id]);
    if (!regRes.rows[0]) return res.status(404).json({ error: 'Caixa aberto não encontrado' });

    const result = await pool.query(
      `INSERT INTO cash_sangrias (cash_register_id, tenant_id, operator_id, operator_name, amount_cents, reason)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [id, tenantId, operatorId || null, operatorName || null, Math.round(parseFloat(amount) * 100), reason || null]
    );
    log('WARN', 'SANGRIA', { caixaId: id, valor: amount, motivo: reason || '—', operador: operatorName });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// COMANDAS
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/comandas?sessionId= — listar comandas de uma sessão com totais
app.get('/api/comandas', requireAuth, async (req, res) => {
  const { sessionId } = req.query;
  if (!sessionId) return res.status(400).json({ error: 'sessionId obrigatório' });
  try {
    const result = await pool.query(`
      SELECT c.*,
        COALESCE((
          SELECT SUM(oi.quantity * oi.unit_price_cents)
          FROM order_items oi
          JOIN orders o ON o.id = oi.order_id
          WHERE o.comanda_id = c.id AND o.status != 'CANCELLED'
        ), 0) AS subtotal_live
      FROM comandas c
      WHERE c.session_id = $1
      ORDER BY c.created_at ASC
    `, [sessionId]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/comandas — criar comanda + upsert CRM customer
app.post('/api/comandas', async (req, res) => {
  const { sessionId, tenantId, name, phone } = req.body;
  if (!sessionId || !tenantId || !name?.trim()) {
    return res.status(400).json({ error: 'sessionId, tenantId e name são obrigatórios' });
  }
  try {
    const session = await pool.query(
      "SELECT id FROM table_sessions WHERE id=$1 AND status='OPEN'", [sessionId]
    );
    if (!session.rows[0]) return res.status(404).json({ error: 'Sessão não encontrada ou fechada' });

    // Upsert customer (apenas se tiver telefone)
    let customerId = null;
    if (phone?.trim()) {
      const customerRes = await pool.query(`
        INSERT INTO customers (tenant_id, name, phone, visit_count, last_visit_at)
        VALUES ($1, $2, $3, 1, NOW())
        ON CONFLICT (tenant_id, phone) DO UPDATE SET
          name = EXCLUDED.name,
          visit_count = customers.visit_count + 1,
          last_visit_at = NOW(),
          updated_at = NOW()
        RETURNING id
      `, [tenantId, name.trim(), phone.trim()]);
      customerId = customerRes.rows[0].id;
    }

    const result = await pool.query(
      `INSERT INTO comandas (session_id, tenant_id, name, phone, customer_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [sessionId, tenantId, name.trim(), phone?.trim() || null, customerId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/comandas/:id/pay — fechar uma comanda individualmente
app.patch('/api/comandas/:id/pay', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { paymentMethod, serviceCharge } = req.body;
  try {
    // Calcula subtotal
    const subtotalRes = await pool.query(`
      SELECT COALESCE(SUM(oi.quantity * oi.unit_price_cents), 0) AS subtotal
      FROM order_items oi
      JOIN orders o ON o.id = oi.order_id
      WHERE o.comanda_id = $1 AND o.status != 'CANCELLED'
    `, [id]);
    const subtotal = parseInt(subtotalRes.rows[0].subtotal);
    const service = serviceCharge ? Math.round(subtotal * 0.1) : 0;
    const total = subtotal + service;

    const result = await pool.query(`
      UPDATE comandas SET
        status='PAID', paid_at=NOW(),
        payment_method=$1,
        subtotal_cents=$2, service_cents=$3, total_cents=$4
      WHERE id=$5 RETURNING *
    `, [paymentMethod || 'CASH', subtotal, service, total, id]);

    if (!result.rows[0]) return res.status(404).json({ error: 'Comanda não encontrada' });
    log('INFO', 'COMANDA_PAGA', { comandaId: id, total: (total/100).toFixed(2), metodo: paymentMethod || 'CASH', servico: serviceCharge ? 'sim' : 'nao' });
    res.json(result.rows[0]);
  } catch (err) {
    log('ERROR', 'ERRO_INTERNO', { msg: err?.message || String(err) }); console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Orders already accept comanda_id via the body — just need to save it

// ════════════════════════════════════════════════════════════════════════════════
// CRM DE CLIENTES
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/crm/customers?tenantId=&search=&filter=&page=
app.get('/api/crm/customers', requireAuth, async (req, res) => {
  const { tenantId, search = '', filter = 'all', page = 1, limit = 30 } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  // Verifica se o plano inclui CRM
  const { limits, planName } = await getPlanLimits(tenantId);
  if (!limits.crm) {
    return res.status(403).json({
      error: `CRM não está disponível no plano ${planName || 'atual'}. Faça upgrade para o plano Pro ou Premium.`,
      code: 'PLAN_LIMIT_CRM',
    });
  }
  const offset = (parseInt(page) - 1) * parseInt(limit);

  let whereExtra = '';
  if (filter === 'inactive15') whereExtra = "AND last_visit_at < NOW() - INTERVAL '15 days'";
  else if (filter === 'inactive30') whereExtra = "AND last_visit_at < NOW() - INTERVAL '30 days'";
  else if (filter === 'frequent') whereExtra = 'AND visit_count >= 5';
  else if (filter === 'vip') whereExtra = "AND total_spent_cents >= 20000";

  try {
    const result = await pool.query(`
      SELECT *,
        EXTRACT(DAY FROM NOW() - last_visit_at)::int AS days_since_last_visit
      FROM customers
      WHERE tenant_id = $1
        AND ($2 = '' OR name ILIKE $3 OR phone ILIKE $3)
        ${whereExtra}
      ORDER BY last_visit_at DESC
      LIMIT $4 OFFSET $5
    `, [tenantId, search, `%${search}%`, limit, offset]);

    const total = await pool.query(`
      SELECT COUNT(*) FROM customers
      WHERE tenant_id = $1
        AND ($2 = '' OR name ILIKE $3 OR phone ILIKE $3)
        ${whereExtra}
    `, [tenantId, search, `%${search}%`]);

    res.json({ customers: result.rows, total: parseInt(total.rows[0].count), page: parseInt(page) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/crm/customers/:id?tenantId= — perfil completo do cliente
app.get('/api/crm/customers/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { tenantId } = req.query;
  try {
    const customerRes = await pool.query(`
      SELECT *,
        EXTRACT(DAY FROM NOW() - last_visit_at)::int AS days_since_last_visit
      FROM customers WHERE id = $1 AND tenant_id = $2
    `, [id, tenantId]);
    if (!customerRes.rows[0]) return res.status(404).json({ error: 'Cliente não encontrado' });

    // Histórico de visitas (comandas)
    const visitsRes = await pool.query(`
      SELECT
        c.id, c.name, c.created_at, c.status,
        ts.opened_at, ts.closed_at,
        t.code AS table_code, t.name AS table_name,
        COALESCE((
          SELECT SUM(oi.qty * oi.unit_price_cents)
          FROM order_items oi
          JOIN orders o ON o.id = oi.order_id
          WHERE o.comanda_id = c.id AND o.status != 'CANCELLED'
        ), 0) AS spent_cents
      FROM comandas c
      JOIN table_sessions ts ON ts.id = c.session_id
      JOIN tables t ON t.id = ts.table_id
      WHERE c.customer_id = $1
      ORDER BY c.created_at DESC
      LIMIT 20
    `, [id]);

    // Top produtos do cliente
    const productsRes = await pool.query(`
      SELECT p.name, SUM(oi.qty) AS qty, SUM(oi.qty * oi.unit_price_cents) AS revenue
      FROM order_items oi
      JOIN orders o ON o.id = oi.order_id
      JOIN products p ON p.id = oi.product_id
      JOIN comandas c ON c.id = o.comanda_id
      WHERE c.customer_id = $1 AND o.status != 'CANCELLED'
      GROUP BY p.name ORDER BY qty DESC LIMIT 10
    `, [id]);

    // Atualiza total_spent e favorite_products no customer
    const totalSpent = visitsRes.rows.reduce((s, v) => s + parseInt(v.spent_cents), 0);
    await pool.query(`
      UPDATE customers SET
        total_spent_cents = $1,
        favorite_products = $2,
        updated_at = NOW()
      WHERE id = $3
    `, [totalSpent, JSON.stringify(productsRes.rows), id]);

    res.json({
      ...customerRes.rows[0],
      total_spent_cents: totalSpent,
      visits: visitsRes.rows,
      top_products: productsRes.rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/crm/customers/:id
app.delete('/api/crm/customers/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    // Desvincula comandas antes de deletar
    await pool.query('UPDATE comandas SET customer_id = NULL WHERE customer_id = $1', [id]);
    await pool.query('DELETE FROM customers WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/crm/customers/:id — atualizar notas/tags do cliente
app.patch('/api/crm/customers/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { notes, tags } = req.body;
  try {
    const result = await pool.query(`
      UPDATE customers SET
        notes = COALESCE($1, notes),
        tags = COALESCE($2, tags),
        updated_at = NOW()
      WHERE id = $3 RETURNING *
    `, [notes ?? null, tags ?? null, id]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/crm/stats?tenantId= — resumo geral do CRM
app.get('/api/crm/stats', requireAuth, async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  try {
    const stats = await pool.query(`
      SELECT
        COUNT(*) AS total_customers,
        COUNT(*) FILTER (WHERE last_visit_at >= NOW() - INTERVAL '30 days') AS active_30d,
        COUNT(*) FILTER (WHERE last_visit_at < NOW() - INTERVAL '15 days') AS inactive_15d,
        COUNT(*) FILTER (WHERE last_visit_at < NOW() - INTERVAL '30 days') AS inactive_30d,
        COUNT(*) FILTER (WHERE visit_count >= 5) AS frequent,
        COALESCE(AVG(total_spent_cents), 0)::int AS avg_spent,
        COALESCE(AVG(visit_count), 0)::numeric(5,1) AS avg_visits
      FROM customers WHERE tenant_id = $1
    `, [tenantId]);
    res.json(stats.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});