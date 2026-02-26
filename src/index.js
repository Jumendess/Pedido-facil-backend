import express from 'express';
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
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: function(origin, callback) {
    // Permite localhost e qualquer subdominio vercel.app
    const allowed = [
      'http://localhost:8080',
      'http://localhost:5173',
      'http://localhost:3000',
    ];
    if (!origin) return callback(null, true); // permite requests sem origin (mobile, curl)
    if (allowed.includes(origin) || origin.endsWith('.vercel.app')) {
      return callback(null, true);
    }
    return callback(null, true); // em produção libera tudo por enquanto
  },
  credentials: true,
}));
app.use(express.json());

// Serve uploaded files statically
app.use('/uploads', express.static(UPLOADS_DIR));

// POST /api/tenant/:id/logo — upload de logo
app.post('/api/tenant/:id/logo', upload.single('logo'), async (req, res) => {
  const { id } = req.params;
  if (!req.file) return res.status(400).json({ error: 'Arquivo não enviado' });
  try {
    // Remove logo anterior se existir
    const old = await pool.query('SELECT logo_url FROM tenants WHERE id=$1', [id]);
    const oldUrl = old.rows[0]?.logo_url;
    if (oldUrl && oldUrl.startsWith('/uploads/')) {
      const oldPath = path.join(__dirname, '../..', oldUrl);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    const logoUrl = `/uploads/${req.file.filename}`;
    await pool.query('UPDATE tenants SET logo_url=$1 WHERE id=$2', [logoUrl, id]);
    res.json({ logo_url: logoUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao salvar logo' });
  }
});

// ─── AUTH ────────────────────────────────────────────────────────────────────

// POST /api/auth/login
// Autentica tenant pelo email/senha usando a função tenant_login do banco
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios' });
  }

  try {
    // Usa a função PostgreSQL tenant_login que verifica o bcrypt hash
    const result = await pool.query(
      'SELECT tenant_login($1, $2) AS tenant_id',
      [email, password]
    );

    const tenantId = result.rows[0]?.tenant_id;
    if (!tenantId) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    // Busca dados do tenant
    const tenantResult = await pool.query(
      'SELECT id, name, slug, email, logo_url, cnpj, phone, is_active, created_at FROM tenants WHERE id = $1',
      [tenantId]
    );
    const tenant = tenantResult.rows[0];

    // Busca o usuário ADMIN associado ao tenant (pelo email do tenant ou primeiro admin)
    const userResult = await pool.query(
      `SELECT id, tenant_id, name, email, pin, role, is_active, created_at
       FROM users
       WHERE tenant_id = $1 AND is_active = TRUE AND role = 'ADMIN'
       ORDER BY created_at ASC
       LIMIT 1`,
      [tenantId]
    );

    // Se não encontrou admin, busca qualquer usuário ativo
    let user = userResult.rows[0];
    if (!user) {
      const anyUser = await pool.query(
        `SELECT id, tenant_id, name, email, pin, role, is_active, created_at
         FROM users WHERE tenant_id = $1 AND is_active = TRUE LIMIT 1`,
        [tenantId]
      );
      user = anyUser.rows[0] || null;
    }

    return res.json({ tenant, user });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ─── TABLES ──────────────────────────────────────────────────────────────────

// GET /api/tables?tenantId=xxx
app.get('/api/tables', async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT id, tenant_id, code, name, is_active, created_at FROM tables WHERE tenant_id = $1 ORDER BY code',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar mesas' });
  }
});

// POST /api/tables
app.post('/api/tables', async (req, res) => {
  const { tenantId, code, name } = req.body;
  if (!tenantId || !code) return res.status(400).json({ error: 'tenantId e code são obrigatórios' });

  try {
    const result = await pool.query(
      'INSERT INTO tables (tenant_id, code, name) VALUES ($1, $2, $3) RETURNING *',
      [tenantId, code, name || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar mesa' });
  }
});

// PATCH /api/tables/:id
app.patch('/api/tables/:id', async (req, res) => {
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
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar mesa' });
  }
});

// DELETE /api/tables/:id
app.delete('/api/tables/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE tables SET is_active = FALSE WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao remover mesa' });
  }
});

// ─── CATEGORIES ──────────────────────────────────────────────────────────────

// GET /api/categories?tenantId=xxx
app.get('/api/categories', async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT * FROM menu_categories WHERE tenant_id = $1 ORDER BY sort_order, name',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar categorias' });
  }
});

// POST /api/categories
app.post('/api/categories', async (req, res) => {
  const { tenantId, name, sort_order } = req.body;
  if (!tenantId || !name) return res.status(400).json({ error: 'tenantId e name são obrigatórios' });

  try {
    const result = await pool.query(
      'INSERT INTO menu_categories (tenant_id, name, sort_order) VALUES ($1, $2, $3) RETURNING *',
      [tenantId, name, sort_order || 0]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar categoria' });
  }
});

// PATCH /api/categories/:id
app.patch('/api/categories/:id', async (req, res) => {
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
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar categoria' });
  }
});

// DELETE /api/categories/:id
app.delete('/api/categories/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE menu_categories SET is_active = FALSE WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao remover categoria' });
  }
});

// ─── PRODUCTS ────────────────────────────────────────────────────────────────

// GET /api/products?tenantId=xxx
app.get('/api/products', async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT * FROM products WHERE tenant_id = $1 ORDER BY sort_order, name',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar produtos' });
  }
});

// POST /api/products
app.post('/api/products', async (req, res) => {
  const { tenantId, category_id, name, description, price_cents, sector, sort_order, image_url } = req.body;
  if (!tenantId || !name || price_cents == null || !sector) {
    return res.status(400).json({ error: 'Campos obrigatórios: tenantId, name, price_cents, sector' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO products (tenant_id, category_id, name, description, price_cents, sector, sort_order, image_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [tenantId, category_id || null, name, description || null, price_cents, sector, sort_order || 0, image_url || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar produto' });
  }
});

// PATCH /api/products/:id
app.patch('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  const { category_id, name, description, price_cents, sector, is_active, sort_order, image_url } = req.body;

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
        image_url = COALESCE($8, image_url)
       WHERE id = $9 RETURNING *`,
      [category_id, name, description, price_cents, sector, is_active, sort_order, image_url !== undefined ? image_url : null, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Produto não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar produto' });
  }
});

// DELETE /api/products/:id
app.delete('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE products SET is_active = FALSE WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao remover produto' });
  }
});

// ─── USERS ───────────────────────────────────────────────────────────────────

// GET /api/users?tenantId=xxx
app.get('/api/users', async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT id, tenant_id, name, email, pin, role, is_active, created_at FROM users WHERE tenant_id = $1 ORDER BY name',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar usuários' });
  }
});

// POST /api/users
app.post('/api/users', async (req, res) => {
  const { tenantId, name, email, password, pin, role } = req.body;
  if (!tenantId || !name || !role) {
    return res.status(400).json({ error: 'Campos obrigatórios: tenantId, name, role' });
  }

  try {
    const passwordHash = password
      ? (await pool.query('SELECT auth_hash_password($1) AS h', [password])).rows[0].h
      : null;

    const result = await pool.query(
      `INSERT INTO users (tenant_id, name, email, password_hash, pin, role)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, tenant_id, name, email, pin, role, is_active, created_at`,
      [tenantId, name, email || null, passwordHash, pin || null, role]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

// PATCH /api/users/:id
app.patch('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const { name, email, pin, role, is_active, password } = req.body;

  try {
    let passwordHash = undefined;
    if (password) {
      passwordHash = (await pool.query('SELECT auth_hash_password($1) AS h', [password])).rows[0].h;
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
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// DELETE /api/users/:id
app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE users SET is_active = FALSE WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao remover usuário' });
  }
});

// ─── SESSIONS ────────────────────────────────────────────────────────────────

// GET /api/sessions?tenantId=xxx
app.get('/api/sessions', async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      `SELECT * FROM table_sessions WHERE tenant_id = $1 ORDER BY opened_at DESC`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
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

    res.json({ sessionId, tenantId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Erro ao abrir sessão' });
  }
});

// POST /api/sessions/close
app.post('/api/sessions/close', async (req, res) => {
  const { sessionId, closedBy, method, amountCents } = req.body;
  if (!sessionId || !method) return res.status(400).json({ error: 'sessionId e method são obrigatórios' });

  try {
    await pool.query(
      'SELECT close_table_session($1, $2, $3, $4)',
      [sessionId, closedBy || null, method, amountCents || 0]
    );

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

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || 'Erro ao fechar sessão' });
  }
});

// ─── ORDERS ──────────────────────────────────────────────────────────────────

// GET /api/orders?tenantId=xxx
app.get('/api/orders', async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT * FROM orders WHERE tenant_id = $1 ORDER BY created_at DESC',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
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
    }

    await client.query('COMMIT');
    res.status(201).json(order);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar pedido' });
  } finally {
    client.release();
  }
});

// PATCH /api/orders/:id/status
app.patch('/api/orders/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: 'status obrigatório' });

  try {
    const result = await pool.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Pedido não encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar pedido' });
  }
});

// ─── ORDER ITEMS ─────────────────────────────────────────────────────────────

// GET /api/order-items?tenantId=xxx
app.get('/api/order-items', async (req, res) => {
  const { tenantId } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });

  try {
    const result = await pool.query(
      'SELECT * FROM order_items WHERE tenant_id = $1',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar itens' });
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

app.listen(PORT, () => {
  console.log(`🚀 Backend rodando em http://localhost:${PORT}`);
});

// ─── ROTAS PÚBLICAS (cliente via QR Code) ─────────────────────────────────────

// GET /api/public/menu/:slug  — retorna cardápio do restaurante sem autenticação
app.get('/api/public/menu/:slug', async (req, res) => {
  const { slug } = req.params;
  try {
    const tenantResult = await pool.query(
      'SELECT id, name, logo_url, description FROM tenants WHERE slug = $1 AND is_active = TRUE',
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
      products: productsResult.rows,
      categories: categoriesResult.rows,
    });
  } catch (err) {
    console.error(err);
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
    res.status(201).json({ orderId: order.id });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Erro ao registrar pedido' });
  } finally {
    client.release();
  }
});

// GET /api/public/session/:sessionId/orders — pedidos da sessão para o cliente
app.get('/api/public/session/:sessionId/orders', async (req, res) => {
  const { sessionId } = req.params;
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
    console.error(err);
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
    console.error(err);
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
app.get('/api/bill-requests', async (req, res) => {
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
    console.error(err);
    res.status(500).json({ error: 'Erro' });
  }
});

// PATCH /api/bill-requests/:id/seen  — garçom marca como visto
app.patch('/api/bill-requests/:id/seen', async (req, res) => {
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
    console.error(err);
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
    console.error(err);
    res.status(500).json({ error: 'Erro' });
  }
});

// POST /api/waiter/login — login do garçom (busca user por email/senha dentro do tenant)
app.post('/api/waiter/login', async (req, res) => {
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

    res.json({
      userId: user.id,
      userName: user.name,
      userRole: user.role,
      tenantId: user.tenant_id,
      tenantName: user.tenant_name,
      slug: user.slug,
    });
  } catch (err) {
    console.error(err);
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
         t.code AS table_code, t.name AS table_name,
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
       JOIN order_items oi       ON oi.order_id  = o.id
       JOIN products p           ON p.id         = oi.product_id
       JOIN table_sessions ts    ON ts.id         = o.session_id
       JOIN tables t             ON t.id          = ts.table_id
       WHERE o.tenant_id = $1
         AND o.status IN ('NEW','PREPARING','READY')
         AND p.sector = $2
       GROUP BY o.id, t.code, t.name
       ORDER BY
         CASE o.status WHEN 'NEW' THEN 0 WHEN 'PREPARING' THEN 1 ELSE 2 END,
         o.created_at ASC`,
      [tenantId, sectorUpper]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar pedidos KDS' });
  }
});

// ─── TENANT SETTINGS ──────────────────────────────────────────────────────────

// GET /api/tenant/:id — busca dados completos do tenant
app.get('/api/tenant/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT id, name, slug, email, cnpj, phone, address, city, state,
              zip_code, logo_url, description, is_active, created_at
       FROM tenants WHERE id = $1`,
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Empresa não encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar dados da empresa' });
  }
});

// PATCH /api/tenant/:id — atualiza dados do tenant
app.patch('/api/tenant/:id', async (req, res) => {
  const { id } = req.params;
  const { name, email, cnpj, phone, address, city, state, zip_code, logo_url, description } = req.body;
  try {
    const result = await pool.query(
      `UPDATE tenants SET
         name        = COALESCE($1, name),
         email       = COALESCE($2, email),
         cnpj        = $3,
         phone       = $4,
         address     = $5,
         city        = $6,
         state       = $7,
         zip_code    = $8,
         logo_url    = $9,
         description = $10
       WHERE id = $11
       RETURNING id, name, slug, email, cnpj, phone, address, city, state, zip_code, logo_url, description, is_active, created_at`,
      [name, email, cnpj || null, phone || null, address || null, city || null,
       state || null, zip_code || null, logo_url || null, description || null, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Empresa não encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar dados da empresa' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// SUPER ADMIN — autenticação e painel SaaS
// ════════════════════════════════════════════════════════════════════════════════

// Middleware simples de auth super admin (token em header)
function superAdminAuth(req, res, next) {
  const token = req.headers['x-super-token'];
  if (!token) return res.status(401).json({ error: 'Token obrigatório' });
  try {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString());
    if (!payload.superAdminId || !payload.exp || Date.now() > payload.exp) {
      return res.status(401).json({ error: 'Token inválido ou expirado' });
    }
    req.superAdminId = payload.superAdminId;
    next();
  } catch { return res.status(401).json({ error: 'Token inválido' }); }
}

function makeSuperToken(id) {
  const payload = { superAdminId: id, exp: Date.now() + 8 * 60 * 60 * 1000 }; // 8h
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

// POST /api/super/login
app.post('/api/super/login', async (req, res) => {
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
    res.json({ id: admin.id, name: admin.name, email: admin.email, token: makeSuperToken(admin.id) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erro interno' }); }
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
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erro' }); }
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
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erro' }); }
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

    const adminPasswordHash = (await client.query('SELECT auth_hash_password($1) AS h', [adminPassword])).rows[0].h;

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
    res.status(201).json(tenant);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
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
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erro' }); }
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
    const result = await pool.query(
      `SELECT i.*, t.name AS tenant_name, p.name AS plan_name
       FROM invoices i
       JOIN tenants t ON t.id = i.tenant_id
       LEFT JOIN plans p ON p.id = i.plan_id
       ${status ? `WHERE i.status = '${status}'` : ''}
       ORDER BY i.due_date DESC LIMIT 100`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: 'Erro' }); }
});

// ════════════════════════════════════════════════════════════════════════════════
// RELATÓRIOS
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/reports/overview?tenantId=&from=&to=
app.get('/api/reports/overview', async (req, res) => {
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
          DATE(p.created_at)        AS day,
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
    console.error(err);
    res.status(500).json({ error: 'Erro ao gerar relatório' });
  }
});

// GET /api/reports/history?tenantId=&from=&to=&page=&limit=
app.get('/api/reports/history', async (req, res) => {
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
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar histórico' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// UPLOAD DE FOTO DE PRODUTO
// ════════════════════════════════════════════════════════════════════════════════

// POST /api/products/:id/image
app.post('/api/products/:id/image', uploadProduct.single('image'), async (req, res) => {
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
    res.json({ image_url: imageUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao salvar imagem: ' + err.message });
  }
});

// DELETE /api/products/:id/image
app.delete('/api/products/:id/image', async (req, res) => {
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
    console.error(err);
    res.status(500).json({ error: 'Erro ao remover imagem' });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// IMPORTAÇÃO CSV DE PRODUTOS
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/products/csv-template  — baixar modelo CSV
app.get('/api/products/csv-template', (req, res) => {
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
app.post('/api/products/csv-import', uploadCSV.single('csv'), async (req, res) => {
  const { tenantId } = req.body;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

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

    res.json({
      success: true,
      imported: inserted.length,
      errors: errors.length,
      errorDetails: errors,
      products: inserted,
    });
  } catch (err) {
    console.error(err);
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
  console.log('📊 Gerando relatórios mensais...');
  const now   = new Date();
  const year  = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();
  const month = now.getMonth() === 0 ? 12 : now.getMonth();
  try {
    const tenants = await pool.query("SELECT id FROM tenants WHERE status = 'ACTIVE'");
    for (const t of tenants.rows) {
      await generateMonthlyReport(t.id, year, month);
    }
    console.log(`✅ Relatórios de ${month}/${year} gerados para ${tenants.rows.length} tenants`);
  } catch (err) {
    console.error('Erro ao gerar relatórios mensais:', err);
  }
});

// DELETE /api/monthly-reports/:id
app.delete('/api/monthly-reports/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM monthly_reports WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/monthly-reports?tenantId= — listar relatórios do tenant
app.get('/api/monthly-reports', async (req, res) => {
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
app.get('/api/monthly-reports/:year/:month', async (req, res) => {
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
app.post('/api/monthly-reports/generate', async (req, res) => {
  const { tenantId, year, month } = req.body;
  if (!tenantId || !year || !month) return res.status(400).json({ error: 'tenantId, year e month obrigatórios' });
  try {
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
app.get('/api/cash-register/current', async (req, res) => {
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
    res.json(result.rows[0] || null);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/cash-register/history?tenantId= — histórico de caixas fechados
app.get('/api/cash-register/history', async (req, res) => {
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
app.get('/api/cash-register/:id', async (req, res) => {
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
app.post('/api/cash-register/open', async (req, res) => {
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
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/cash-register/:id/close — fechar caixa
app.post('/api/cash-register/:id/close', async (req, res) => {
  const { id } = req.params;
  const { closingBalance, notes } = req.body;
  try {
    const regRes = await pool.query("SELECT * FROM cash_registers WHERE id=$1 AND status='OPEN'", [id]);
    if (!regRes.rows[0]) return res.status(404).json({ error: 'Caixa aberto não encontrado' });
    const reg = regRes.rows[0];

    // Calcula totais de pagamentos desde abertura
    const totals = await pool.query(`
      SELECT
        COALESCE(SUM(amount_cents), 0) AS total,
        COALESCE(SUM(CASE WHEN method='CASH'  THEN amount_cents ELSE 0 END), 0) AS cash,
        COALESCE(SUM(CASE WHEN method='PIX'   THEN amount_cents ELSE 0 END), 0) AS pix,
        COALESCE(SUM(CASE WHEN method='CARD'  THEN amount_cents ELSE 0 END), 0) AS card,
        COALESCE(SUM(CASE WHEN method='OTHER' THEN amount_cents ELSE 0 END), 0) AS other
      FROM payments p
      JOIN table_sessions ts ON ts.id = p.session_id
      WHERE ts.tenant_id=$1 AND p.paid_at >= $2
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
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/cash-register/:id/sangria — registrar retirada
app.post('/api/cash-register/:id/sangria', async (req, res) => {
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
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════════
// COMANDAS
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/comandas?sessionId= — listar comandas de uma sessão com totais
app.get('/api/comandas', async (req, res) => {
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
app.patch('/api/comandas/:id/pay', async (req, res) => {
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
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Patch existing create order route to accept comanda_id
// Orders already accept comanda_id via the body — just need to save it

// ════════════════════════════════════════════════════════════════════════════════
// CRM DE CLIENTES
// ════════════════════════════════════════════════════════════════════════════════

// GET /api/crm/customers?tenantId=&search=&filter=&page=
app.get('/api/crm/customers', async (req, res) => {
  const { tenantId, search = '', filter = 'all', page = 1, limit = 30 } = req.query;
  if (!tenantId) return res.status(400).json({ error: 'tenantId obrigatório' });
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
app.get('/api/crm/customers/:id', async (req, res) => {
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
app.delete('/api/crm/customers/:id', async (req, res) => {
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
app.patch('/api/crm/customers/:id', async (req, res) => {
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
app.get('/api/crm/stats', async (req, res) => {
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