// Script de teste de e-mail — rode com: node test-email.mjs
// Substitua SUA_CHAVE_AQUI pela sua RESEND_API_KEY

import { Resend } from 'resend';

const RESEND_API_KEY = process.env.RESEND_API_KEY || 'COLE_SUA_CHAVE_AQUI';
const PARA           = 'julio.mendes60@gmail.com';
const FRONTEND       = 'https://mesafay.com.br';

if (RESEND_API_KEY === 'COLE_SUA_CHAVE_AQUI') {
  console.error('❌ Defina a RESEND_API_KEY no ambiente ou substitua no script.');
  console.error('   Exemplo: RESEND_API_KEY=re_xxxx node test-email.mjs');
  process.exit(1);
}

const resend = new Resend(RESEND_API_KEY);

console.log(`📧 Enviando e-mail de teste para ${PARA}...`);

const { data, error } = await resend.emails.send({
  from:    'Mesafay <onboarding@resend.dev>',   // domínio de teste do Resend (funciona sem verificar domínio)
  to:      PARA,
  subject: '🎉 Bem-vindo ao Mesafay — Restaurante Teste',
  html: `
<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f6fa;font-family:Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6fa;padding:40px 16px">
    <tr><td align="center">
      <table width="100%" style="max-width:540px;background:#fff;border-radius:20px;overflow:hidden;border:1px solid #e8eaf0">

        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#e8622a 0%,#f5a623 100%);padding:36px 32px;text-align:center">
            <div style="font-size:42px;margin-bottom:8px">🍽️</div>
            <h1 style="margin:0;color:#fff;font-size:1.6rem;font-weight:800">Bem-vindo ao Mesafay!</h1>
            <p style="margin:6px 0 0;color:rgba(255,255,255,0.85);font-size:0.95rem">Restaurante Teste está pronto para decolar</p>
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
                  <td style="padding:8px 0;border-bottom:1px solid #e8eaf0;font-size:0.88rem;font-weight:700;color:#111827">Restaurante Teste</td>
                </tr>
                <tr>
                  <td style="padding:8px 0;border-bottom:1px solid #e8eaf0;font-size:0.82rem;color:#6b7280">E-mail</td>
                  <td style="padding:8px 0;border-bottom:1px solid #e8eaf0;font-size:0.88rem;color:#111827">julio.mendes60@gmail.com</td>
                </tr>
                <tr>
                  <td style="padding:8px 0;font-size:0.82rem;color:#6b7280">Senha</td>
                  <td style="padding:8px 0;font-size:0.88rem;font-weight:700;color:#e8622a;font-family:monospace;letter-spacing:0.05em">SenhaTest@123</td>
                </tr>
              </table>
            </div>

            <p style="margin:0 0 8px;color:#374151;font-size:0.85rem">⏳ Seu período de teste é de <strong>14 dias</strong>. Aproveite!</p>

            <!-- CTA -->
            <table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0">
              <tr>
                <td align="center">
                  <a href="${FRONTEND}/login" style="display:inline-block;background:linear-gradient(135deg,#e8622a,#f5a623);color:#fff;font-weight:800;font-size:0.95rem;text-decoration:none;padding:14px 36px;border-radius:12px">
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
                <li>Pronto! Seus clientes já podem pedir pelo celular 🎉</li>
              </ol>
            </div>

            <p style="margin:0;font-size:0.82rem;color:#6b7280;text-align:center">
              Dúvidas? Responda este e-mail ou acesse <a href="${FRONTEND}" style="color:#e8622a">mesafay.com.br</a>
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f9fafb;padding:20px 32px;text-align:center;border-top:1px solid #f0f2f7">
            <p style="margin:0;font-size:0.75rem;color:#9ca3af">
              © ${new Date().getFullYear()} Mesafay. Todos os direitos reservados.
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

if (error) {
  console.error('❌ Erro ao enviar:', error);
  process.exit(1);
}

console.log('✅ E-mail enviado com sucesso!');
console.log('   ID:', data.id);
console.log('   Verifique a caixa de entrada de', PARA);
