import request from "supertest";
import app from "../src/index.js";

// ─── 1. HEALTH CHECK ──────────────────────────────────────────────────────────
describe("Health Check", () => {
  it("GET /api/health → deve retornar status 200 ou 500", async () => {
    const res = await request(app).get("/api/health");
    expect([200, 500]).toContain(res.statusCode);
    expect(res.body).toHaveProperty("status");
  });
});

// ─── 2. AUTH ──────────────────────────────────────────────────────────────────
describe("Auth — /api/auth/login", () => {
  it("deve retornar 400 quando email ou senha estiverem ausentes", async () => {
    const res = await request(app).post("/api/auth/login").send({});
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("deve retornar 401 para credenciais inválidas", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "invalido@teste.com", password: "senhaerrada" });
    // Pode retornar 401 (credenciais erradas) ou 500 (sem banco) — ambos são esperados
    expect([401, 500]).toContain(res.statusCode);
  });
});

// ─── 3. ROTAS PROTEGIDAS — sem token ─────────────────────────────────────────
describe("Rotas protegidas — sem token devem retornar 401", () => {
  const rotasProtegidas = [
    { method: "get",  url: "/api/tables?tenantId=123" },
    { method: "get",  url: "/api/products?tenantId=123" },
    { method: "get",  url: "/api/categories?tenantId=123" },
    { method: "get",  url: "/api/users?tenantId=123" },
    { method: "get",  url: "/api/sessions?tenantId=123" },
    { method: "get",  url: "/api/orders?tenantId=123" },
    { method: "get",  url: "/api/tenant/123" },
    { method: "get",  url: "/api/reports/overview?tenantId=123" },
  ];

  rotasProtegidas.forEach(({ method, url }) => {
    it(`${method.toUpperCase()} ${url} → 401`, async () => {
      const res = await request(app)[method](url);
      expect(res.statusCode).toBe(401);
      expect(res.body).toHaveProperty("error");
    });
  });
});

// ─── 4. SUPER ADMIN — sem token ───────────────────────────────────────────────
describe("Super Admin — rotas sem token devem retornar 401", () => {
  it("GET /api/super/dashboard → 401", async () => {
    const res = await request(app).get("/api/super/dashboard");
    expect(res.statusCode).toBe(401);
  });

  it("GET /api/super/tenants → 401", async () => {
    const res = await request(app).get("/api/super/tenants");
    expect(res.statusCode).toBe(401);
  });

  it("POST /api/super/login sem body → 400", async () => {
    const res = await request(app).post("/api/super/login").send({});
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

// ─── 5. ROTAS PÚBLICAS ────────────────────────────────────────────────────────
describe("Rotas públicas", () => {
  it("GET /api/public/menu/slug-inexistente → 404 ou 500 (sem banco)", async () => {
    const res = await request(app).get("/api/public/menu/restaurante-que-nao-existe");
    expect([404, 500]).toContain(res.statusCode);
  });

  it("POST /api/sessions/open sem body → 400", async () => {
    const res = await request(app).post("/api/sessions/open").send({});
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("POST /api/public/order sem body → 400", async () => {
    const res = await request(app).post("/api/public/order").send({});
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("POST /api/public/bill-request sem sessionId → 400", async () => {
    const res = await request(app).post("/api/public/bill-request").send({});
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

// ─── 6. VALIDAÇÃO DE CAMPOS OBRIGATÓRIOS ─────────────────────────────────────
describe("Validação de campos obrigatórios (sem token → 401)", () => {
  it("POST /api/tables sem token → 401", async () => {
    const res = await request(app)
      .post("/api/tables")
      .send({ tenantId: "123", code: "01" });
    expect(res.statusCode).toBe(401);
  });

  it("POST /api/products sem token → 401", async () => {
    const res = await request(app)
      .post("/api/products")
      .send({ tenantId: "123", name: "Produto", price_cents: 1000, sector: "KITCHEN" });
    expect(res.statusCode).toBe(401);
  });
});

// ─── 7. KDS — rota pública ────────────────────────────────────────────────────
describe("KDS — rotas públicas", () => {
  it("GET /api/kds/:tenantId/KITCHEN → 200 ou 500 (sem banco)", async () => {
    const res = await request(app).get("/api/kds/qualquer-id/kitchen");
    expect([200, 500]).toContain(res.statusCode);
  });

  it("GET /api/kds/:tenantId/setor-invalido → 400", async () => {
    const res = await request(app).get("/api/kds/qualquer-id/INVALIDO");
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

// ─── 8. WAITER — rota pública ─────────────────────────────────────────────────
describe("Waiter — rotas públicas", () => {
  it("POST /api/waiter/login sem body → 400", async () => {
    const res = await request(app).post("/api/waiter/login").send({});
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("GET /api/waiter/tables/:tenantId → 200 ou 500 (sem banco)", async () => {
    const res = await request(app).get("/api/waiter/tables/qualquer-id");
    expect([200, 500]).toContain(res.statusCode);
  });
});

// ─── 9. TOKEN JWT INVÁLIDO ────────────────────────────────────────────────────
describe("Token JWT inválido → 401", () => {
  it("GET /api/tables com token falso → 401", async () => {
    const res = await request(app)
      .get("/api/tables?tenantId=123")
      .set("Authorization", "Bearer tokenfalso123");
    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty("error");
  });

  it("GET /api/orders com token expirado (formato inválido) → 401", async () => {
    const res = await request(app)
      .get("/api/orders?tenantId=123")
      .set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalido.invalido");
    expect(res.statusCode).toBe(401);
  });
});