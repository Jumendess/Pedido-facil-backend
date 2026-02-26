import pg from 'pg';
import dotenv from 'dotenv';
dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

pool.on('error', (err) => {
  console.error('Unexpected DB error', err);
});

export default pool;
