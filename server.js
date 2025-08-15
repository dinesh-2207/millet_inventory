// server.js

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connection = require('./db'); // db.js with mysql2.createPool().promise()
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123';

app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serves files like login.html

// ✅ Login API
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Missing credentials' });
  }

  try {
    const [rows] = await connection.query('SELECT * FROM users WHERE username = ?', [username]);

    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ success: false, message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id, role: user.userType }, JWT_SECRET, { expiresIn: '2h' });

    res.json({ success: true, token, userType: user.userType });
  } catch (error) {
    console.error('❌ Login Error:', error);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

// ✅ Get warehouse ID by email – for storing in localStorage
app.get("/api/get-warehouse-id", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Missing email" });

  try {
    const [rows] = await connection.query(
      "SELECT id, name FROM warehouses WHERE email = ?",
      [email]
    );
    if (!rows.length) return res.status(404).json({ error: "Warehouse not found" });

    res.json({ id: rows[0].id, name: rows[0].name }); // ✅ send both
  } catch (err) {
    console.error("❌ Get Warehouse ID Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Get distributor ID by email
app.get("/api/get-distributor-id", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Missing email" });

  try {
    const [rows] = await connection.query(
      "SELECT id FROM distributors WHERE email = ?",
      [email]
    );
    if (!rows.length) return res.status(404).json({ error: "Distributor not found" });

    res.json({ id: rows[0].id });
  } catch (err) {
    console.error("❌ Get Distributor ID Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});


// ✅ Product POST routed
app.post('/api/product', async (req, res) => {
  const { pName, sku, ean, unit, qty, mrp } = req.body;

  if (!pName || !sku || !ean || !unit || !qty || !mrp) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  try {
    await connection.query(
      'INSERT INTO products (name, sku, ean, unit, qty, mrp) VALUES (?, ?, ?, ?, ?, ?)',
      [pName, sku, ean, unit, qty, mrp]
    );

    res.json({ success: true, message: '✅ Product added successfully!' });
  } catch (err) {
    console.error('❌ DB Error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ✅ Get Products API
app.get('/api/products', async (req, res) => {
  try {
    const [rows] = await connection.query('SELECT * FROM products');
    res.json({ success: true, products: rows });
  } catch (error) {
    console.error('❌ Fetch Products Error:', error.sqlMessage || error);
    res.status(500).json({ success: false, message: '❌ Error fetching products' });
  }
});
// Add Warehouse
app.post("/add-warehouse", async (req, res) => {
  const { wName, wLocation, wEmail, wPass } = req.body;

  // Basic validation
  if (!wName || !wLocation || !wEmail || !wPass) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }

  let conn;
  try {
    conn = await connection.getConnection(); // ✅ get single connection for transaction

    // Check if email already exists in users
    const [existing] = await conn.query(
      "SELECT id FROM users WHERE username = ?",
      [wEmail]
    );

    if (existing.length > 0) {
      conn.release(); // ✅ release before returning
      return res.status(400).json({
        success: false,
        message: "Email already exists. Please use a different one."
      });
    }

    const hashedPassword = await bcrypt.hash(wPass, 10);

    // ✅ Start transaction
    await conn.beginTransaction();

    // Insert into warehouses
    const [warehouseResult] = await conn.query(
      "INSERT INTO warehouses (name, location, email, password) VALUES (?, ?, ?, ?)",
      [wName, wLocation, wEmail, hashedPassword]
    );

    // Insert into users
    await conn.query(
      "INSERT INTO users (username, password, userType) VALUES (?, ?, ?)",
      [wEmail, hashedPassword, "warehouse"]
    );

    // ✅ Commit transaction
    await conn.commit();

    res.json({
      success: true,
      message: "✅ Warehouse added and login created!",
      warehouseId: warehouseResult.insertId
    });

  } catch (error) {
    console.error("❌ Add Warehouse Error:", error);

    if (conn) {
      try {
        await conn.rollback(); // ✅ rollback if any query failed
      } catch (rollbackError) {
        console.error("Rollback Error:", rollbackError);
      }
    }

    res.status(500).json({ success: false, message: "Error adding warehouse" });
  } finally {
    if (conn) conn.release(); // ✅ always release connection
  }
});

// Get warehouse API
app.get('/api/warehouses', async (req, res) => {
  try {
    // Include id column to send the warehouse ID to frontend
    const [rows] = await connection.query('SELECT id, name, location, email FROM warehouses');
    res.json({ success: true, warehouses: rows });
  } catch (error) {
    console.error('❌ Fetch Warehouses Error:', error);
    res.status(500).json({ success: false, message: 'Error fetching warehouses' });
  }
});

// ✅ POST: Add Distributor with login
app.post("/api/add-distributor", async (req, res) => {
  const { name, email, password, city, warehouse } = req.body;

  if (!name || !email || !password || !city || !warehouse) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into distributors table
    await connection.query(
      `INSERT INTO distributors (name, email, password, city, warehouse) VALUES (?, ?, ?, ?, ?)`,
      [name, email, hashedPassword, city, warehouse]
    );

    // Also insert into users table for login
    await connection.query(
      'INSERT INTO users (username, password, userType) VALUES (?, ?, ?)',
      [email, hashedPassword, 'distributor']
    );

    res.status(200).json({ success: true, message: "Distributor added successfully" });
  } catch (err) {
    console.error("❌ Add Distributor Error:", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
// ✅ GET Distributors API (Filtered by Warehouse)
app.get("/api/distributors", async (req, res) => {
  const { warehouse } = req.query;

  try {
    let query = "SELECT name, city, email, warehouse FROM distributors";
    let params = [];

    if (warehouse) {
      query += " WHERE warehouse = ?";
      params.push(warehouse);
    }

    const [rows] = await connection.query(query, params);
    res.json({ success: true, distributors: rows });
  } catch (err) {
    console.error("❌ Fetch Distributors Error:", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Order Status Update (Admin)
app.put('/orders/:id', async (req, res) => {
  const orderId = req.params.id;
  const { status } = req.body;

  try {
    // Step 1: Get existing order info (for distributor/product/qty)
    const [orders] = await connection.query(
      'SELECT warehouse_id, distributor_name, product_name, quantity FROM order_status WHERE order_id = ?',
      [orderId]
    );

    if (orders.length === 0) {
      return res.status(404).json({ error: '❌ Order not found' });
    }

    const { warehouse_id, distributor_name, product_name, quantity } = orders[0];

    // Step 2: Update status in main table
    await connection.query(
      'UPDATE order_status SET status = ? WHERE order_id = ?',
      [status, orderId]
    );

    // Step 3: Insert new row into history table
    await connection.query(
      'INSERT INTO order_status_history (order_id, warehouse_id, distributor_name, product_name, quantity, status) VALUES (?, ?, ?, ?, ?, ?)',
      [orderId, warehouse_id, distributor_name, product_name, quantity, status]
    );

    // ✅ Step 4: If Delivered, update distributor_stock
    if (status === 'Delivered') {
      const [[dist]] = await connection.query(
        'SELECT id FROM distributors WHERE email = ?',
        [distributor_name]
      );
      const [[prod]] = await connection.query(
        'SELECT id FROM products WHERE name = ?',
        [product_name]
      );

      if (dist && prod) {
        const distributorId = dist.id;
        const productId = prod.id;

        await connection.query(`
          INSERT INTO distributor_stock (distributor_id, product_id, qty)
          VALUES (?, ?, ?)
          ON DUPLICATE KEY UPDATE qty = qty + ?
        `, [distributorId, productId, quantity, quantity]);
      }
    }

    // ✅ Step 5: Log it in activity_logs
    const [[wh]] = await connection.query('SELECT name FROM warehouses WHERE id = ?', [warehouse_id]);
const source = `${wh.name} (${distributor_name})`;
await connection.query(
  'INSERT INTO activity_logs (source, description) VALUES (?, ?)',
  [source, `📦 Order #${orderId} updated to "${status}" for ${product_name}`]
);

    res.json({ message: "✅ Order status updated, history recorded, and stock updated if delivered" });

  } catch (error) {
    console.error('❌ Order Update Error:', error.message);
    res.status(500).json({ error: 'Server error while updating order status' });
  }
});

// Admin Activity Logs - GET
app.get('/api/admin/activity-logs', async (req, res) => {
  try {
    const [rows] = await connection.query(`
      SELECT id, source, description, timestamp
      FROM activity_logs
      ORDER BY timestamp DESC
      LIMIT 50
    `);
    res.json({ logs: rows });
  } catch (err) {
    console.error("❌ Admin Activity Logs Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Get Order Status History - Admin API
app.get('/api/admin/order-status', async (req, res) => {
  try {
    const [rows] = await connection.query(`
      SELECT io.id AS orderId,
             w.name AS warehouse,
             d.name AS distributor,
             p.name AS productName,   -- changed alias to match frontend
             io.qty,
             io.status,
             io.created_at
      FROM incoming_orders io
      JOIN warehouses w ON io.warehouse_id = w.id
      JOIN distributors d ON io.distributor_id = d.id
      JOIN products p ON io.product_id = p.id
      ORDER BY io.created_at DESC
      LIMIT 20
    `);

    // Send structured response
    res.json({ success: true, orders: rows });
  } catch (err) {
    console.error('❌ Error fetching order status:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// ==================== WAREHOUSE APIs ====================

// ✅ Get current inventory for a warehouse
app.get('/api/warehouse/inventory', async (req, res) => {
  const { warehouseId } = req.query;
  if (!warehouseId) return res.status(400).json({ success: false, error: "Missing warehouseId" });

  try {
    const [rows] = await connection.query(`
      SELECT 
        p.id AS product_id,
        p.name AS product,
        p.sku,
        p.ean,
        p.unit,
        COALESCE(wi.qty, 0) AS qty,
        p.mrp
      FROM products p
      LEFT JOIN warehouse_inventory wi 
        ON p.id = wi.product_id AND wi.warehouse_id = ?
    `, [warehouseId]);

    res.json({ success: true, inventory: rows });
  } catch (err) {
    console.error("❌ Warehouse Inventory Error:", err.message);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ✅ Add stock or update existing stock
app.post("/api/add-stock", async (req, res) => {
  const { warehouseId, sku, qty } = req.body;

  if (!warehouseId || !sku || isNaN(qty) || qty <= 0) {
    return res.status(400).json({ error: "Invalid input: warehouseId, SKU, and qty must be positive" });
  }

  try {
    // Get product
    const [productRow] = await connection.query(
      "SELECT id, name FROM products WHERE sku = ?",
      [sku]
    );
    if (!productRow.length) return res.status(404).json({ error: "❌ Product not found" });

    const { id: productId, name: productName } = productRow[0];

    // Update or insert stock
    await connection.query(`
      INSERT INTO warehouse_inventory (warehouse_id, product_id, qty)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE qty = qty + VALUES(qty)
    `, [warehouseId, productId, qty]);

    // Log activity
    const [[warehouse]] = await connection.query('SELECT name FROM warehouses WHERE id = ?', [warehouseId]);
    const source = `${warehouse.name} (Admin)`;
    await connection.query(
      'INSERT INTO activity_logs (source, description) VALUES (?, ?)',
      [source, `➕ Added ${qty} stock for ${productName}`]
    );

    res.json({ success: true, message: "✅ Stock added successfully" });
  } catch (err) {
    console.error("❌ Error adding stock:", err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---------------------- INCOMING ORDERS (WAREHOUSE) ----------------------
// GET /api/warehouse/orders?warehouseId=123[&status=Pending|Shipped|Delivered]
app.get("/api/warehouse/orders", async (req, res) => {
  try {
    const { warehouseId, status } = req.query;
    if (!warehouseId) {
      return res.status(400).json({ error: "Missing warehouseId" });
    }

    // Main orders list (filtered by warehouse and optional status)
    const params = [warehouseId];
    let statusWhere = "";
    if (status && ["Pending", "Shipped", "Delivered"].includes(status)) {
      statusWhere = " AND o.status = ? ";
      params.push(status);
    }

    const [orders] = await connection.query(
      `
      SELECT 
        o.id,
        w.name AS warehouseName,
        d.name AS distributorName,
        p.name AS productName,
        o.qty       AS quantity,
        -- Normalize status casing when returning
        CONCAT(UPPER(SUBSTRING(o.status,1,1)), LOWER(SUBSTRING(o.status,2))) AS status,
        o.order_date AS created_at
      FROM distributor_orders o
      JOIN warehouses   w ON o.warehouse_id   = w.id
      JOIN distributors d ON o.distributor_id = d.id
      JOIN products     p ON o.product_id     = p.id
      WHERE o.warehouse_id = ?
      ${statusWhere}
      ORDER BY o.order_date DESC
      `,
      params
    );

    // Status summary (always computed for the warehouse, irrespective of filter)
    const [summaryRows] = await connection.query(
      `
      SELECT 
        CONCAT(UPPER(SUBSTRING(status,1,1)), LOWER(SUBSTRING(status,2))) AS status,
        COUNT(*) AS cnt
      FROM distributor_orders
      WHERE warehouse_id = ?
      GROUP BY status
      `,
      [warehouseId]
    );

    const summary = { Pending: 0, Shipped: 0, Delivered: 0 };
    summaryRows.forEach(r => { summary[r.status] = r.cnt; });

    return res.json({ orders, summary });
  } catch (err) {
    console.error("❌ /api/warehouse/orders error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// POST /api/warehouse/dispatch  { orderId }
app.post("/api/warehouse/dispatch", async (req, res) => {
  try {
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ message: "Missing orderId" });

    // Only allow Pending -> Shipped
    const [check] = await connection.query(
      "SELECT id, status FROM distributor_orders WHERE id = ?",
      [orderId]
    );
    if (check.length === 0) {
      return res.status(404).json({ message: "Order not found" });
    }
    if (check[0].status !== "Pending") {
      return res.status(400).json({ message: "Only Pending orders can be dispatched" });
    }

    const [result] = await connection.query(
      "UPDATE distributor_orders SET status = 'Shipped' WHERE id = ? AND status = 'Pending'",
      [orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(400).json({ message: "Order already dispatched or status changed" });
    }

    return res.json({ success: true, message: "Order dispatched successfully" });
  } catch (err) {
    console.error("❌ /api/warehouse/dispatch error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});
// -------------------------------------------------------------------------

// ✅ Customer purchase
app.post('/api/warehouse/purchase', async (req, res) => {
  const { warehouseId, customerName, productName, quantity } = req.body;
  if (!warehouseId || !customerName || !productName || !quantity || quantity <= 0) {
    return res.status(400).json({ error: '❌ Missing or invalid required fields' });
  }

  try {
    const [[product]] = await connection.query('SELECT id FROM products WHERE name = ?', [productName]);
    if (!product) return res.status(404).json({ error: '❌ Product not found' });

    const [[inventory]] = await connection.query(
      'SELECT qty FROM warehouse_inventory WHERE warehouse_id = ? AND product_id = ?',
      [warehouseId, product.id]
    );
    if (!inventory || inventory.qty < quantity) return res.status(400).json({ error: '❌ Not enough stock' });

    const [[warehouse]] = await connection.query('SELECT name FROM warehouses WHERE id = ?', [warehouseId]);
    if (!warehouse) return res.status(404).json({ error: '❌ Warehouse not found' });

    await connection.query(
      'UPDATE warehouse_inventory SET qty = qty - ? WHERE warehouse_id = ? AND product_id = ?',
      [quantity, warehouseId, product.id]
    );

    await connection.query(
      'INSERT INTO customer_purchases (warehouse_name, customer_name, product_name, quantity, purchase_date) VALUES (?, ?, ?, ?, NOW())',
      [warehouse.name, customerName, productName, quantity]
    );

    const source = `${warehouse.name} (${customerName})`;
    const description = `${customerName} purchased ${quantity} units of ${productName}`;
    await connection.query('INSERT INTO activity_logs (source, description) VALUES (?, ?)', [source, description]);

    res.json({ success: true, message: '✅ Purchase successful' });
  } catch (err) {
    console.error('❌ Error in purchase:', err);
    res.status(500).json({ error: '❌ Server error' });
  }
});

// ✅ Purchase history
app.get('/api/warehouse/purchase-history', async (req, res) => {
  const { warehouseId } = req.query;
  let query = `SELECT customer_name, product_name, quantity, purchase_date, warehouse_name FROM customer_purchases`;
  const params = [];
  if (warehouseId) {
    query += ' WHERE warehouse_name = (SELECT name FROM warehouses WHERE id = ?)';
    params.push(warehouseId);
  }
  query += ' ORDER BY purchase_date DESC LIMIT 10';

  try {
    const [rows] = await connection.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('❌ Purchase History Error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ✅ Activity Logs - GET by warehouse name
app.get('/api/activity-logs', async (req, res) => {
  let { warehouseName } = req.query;
  if (!warehouseName) return res.status(400).json({ error: 'Missing warehouseName' });
  warehouseName = warehouseName.trim();

  try {
    const [logs] = await connection.query(`
      SELECT id, source, description, timestamp
      FROM activity_logs
      WHERE LOWER(source) LIKE CONCAT(LOWER(?), ' (%)%')
      ORDER BY timestamp DESC
      LIMIT 50
    `, [warehouseName]);

    res.json(logs);
  } catch (err) {
    console.error('❌ Error fetching activity logs:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ✅ Activity Logs - POST new log
app.post('/api/activity-logs', async (req, res) => {
  let { warehouseName, userName, description } = req.body;
  if (!warehouseName || !userName || !description) {
    return res.status(400).json({ error: '❌ Missing warehouseName, userName or description' });
  }

  warehouseName = warehouseName.trim();
  userName = userName.trim();
  description = description.trim();

  try {
    const [[warehouse]] = await connection.query('SELECT name FROM warehouses WHERE name = ?', [warehouseName]);
    if (!warehouse) return res.status(404).json({ error: '❌ Warehouse not found' });

    const source = `${warehouse.name} (${userName})`;
    await connection.query('INSERT INTO activity_logs (source, description, timestamp) VALUES (?, ?, NOW())', [source, description]);

    res.json({ success: true, message: '✅ Log saved' });
  } catch (err) {
    console.error('❌ Error inserting log:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ======================= Distributor Module =======================
// Distributor info - GET
app.get('/api/distributor/info', async (req, res) => {
  const distributorId = req.query.distributorId;
  if (!distributorId) return res.status(400).json({ error: "Missing distributorId" });

  try {
    const [rows] = await connection.query(
      "SELECT id, name, email, warehouse FROM distributors WHERE id = ?",
      [distributorId]
    );

    if (rows.length === 0) return res.status(404).json({ error: "Distributor not found" });

    res.json({ success: true, data: rows[0] });
  } catch (err) {
    console.error("❌ Distributor Info Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// Distributor stock - GET
app.get('/api/distributor/stock', async (req, res) => {
  const distributorId = req.query.distributorId;
  if (!distributorId) return res.status(400).json({ error: "Missing distributorId" });

  try {
    const [rows] = await connection.query(`
      SELECT p.id AS productId, p.name AS productName, p.sku, d.qty, p.mrp
      FROM distributor_stock d
      JOIN products p ON d.product_id = p.id
      WHERE d.distributor_id = ?
    `, [distributorId]);

    res.json({ success: true, stock: rows });
  } catch (err) {
    console.error("❌ Distributor Stock Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =======================
// GET Products for Distributor's Warehouse
// =======================
app.get("/api/distributor/products", async (req, res) => {
  const { distributorId } = req.query;
  if (!distributorId) {
    return res.status(400).json({ error: "Missing distributorId" });
  }

  try {
    // Step 1: Get distributor's warehouse_id
    const [distributor] = await connection.query(
      "SELECT warehouse_id FROM distributors WHERE id = ?",
      [distributorId]
    );
    if (distributor.length === 0) {
      return res.status(404).json({ error: "Distributor not found" });
    }
    const warehouseId = distributor[0].warehouse_id;

    // Step 2: Get products from warehouse_inventory + products
    const [products] = await connection.query(
      `SELECT p.id, p.name, p.price, wi.qty
       FROM warehouse_inventory wi
       JOIN products p ON wi.product_id = p.id
       WHERE wi.warehouse_id = ? AND wi.qty > 0`,
      [warehouseId]
    );

    res.json({ success: true, products });
  } catch (err) {
    console.error("❌ Error fetching distributor products:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =======================
// POST Place Order for Distributor
// =======================
app.post("/api/distributor/orders", async (req, res) => {
  const { distributorId, productId, qty } = req.body;
  if (!distributorId || !productId || !qty) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    // Step 1: Get distributor's warehouse_id
    const [distributor] = await connection.query(
      "SELECT warehouse_id FROM distributors WHERE id = ?",
      [distributorId]
    );
    if (distributor.length === 0) {
      return res.status(404).json({ error: "Distributor not found" });
    }
    const warehouseId = distributor[0].warehouse_id;

    // Step 2: Get warehouse name
    const [warehouse] = await connection.query(
      "SELECT name FROM warehouses WHERE id = ?",
      [warehouseId]
    );
    if (warehouse.length === 0) {
      return res.status(404).json({ error: "Warehouse not found" });
    }
    const warehouseName = warehouse[0].name;

    // Step 3: Insert into distributor_orders
    await connection.query(
      `INSERT INTO distributor_orders (distributor_id, product_id, warehouse, qty)
       VALUES (?, ?, ?, ?)`,
      [distributorId, productId, warehouseName, qty]
    );

    res.json({ success: true, message: "Order placed successfully" });
  } catch (err) {
    console.error("❌ Distributor Orders Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =======================
// GET Orders for Distributor
// =======================
app.get("/api/distributor/orders", async (req, res) => {
  const { distributorId } = req.query;
  if (!distributorId) {
    return res.status(400).json({ error: "Missing distributorId" });
  }

  try {
    const [orders] = await connection.query(
      `SELECT o.id, p.name AS product_name, o.qty, o.status, o.order_date, o.warehouse
       FROM distributor_orders o
       JOIN products p ON o.product_id = p.id
       WHERE o.distributor_id = ?`,
      [distributorId]
    );

    res.json({ success: true, orders });
  } catch (err) {
    console.error("❌ Distributor Orders Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// =======================
// POST Confirm Delivery
// =======================
app.post('/api/distributor/confirm-delivery', async (req, res) => {
  const { orderId } = req.body;
  if (!orderId) {
    return res.status(400).json({ success: false, message: "Missing orderId" });
  }

  try {
    const [result] = await connection.query(
      `UPDATE distributor_orders
       SET status = 'Delivered'
       WHERE id = ? AND LOWER(status) = 'shipped'`,
      [orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Order not found or not shipped" });
    }

    res.json({ success: true, message: "Delivery confirmed" });
  } catch (err) {
    console.error("❌ Confirm Delivery Error:", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Distributor Sales - POST
app.post('/api/distributor/sales', async (req, res) => {
  const { distributorId, productId, qty } = req.body;
  if (!distributorId || !productId || !qty || qty <= 0)
    return res.status(400).json({ error: "Invalid sales data" });

  try {
    const [[stock]] = await connection.query(
      "SELECT qty FROM distributor_stock WHERE distributor_id = ? AND product_id = ?",
      [distributorId, productId]
    );
    if (!stock || stock.qty < qty) return res.status(400).json({ error: "Insufficient stock" });

    await connection.query(
      "INSERT INTO sales (distributor_id, product_id, qty, date) VALUES (?, ?, ?, NOW())",
      [distributorId, productId, qty]
    );

    await connection.query(
      "UPDATE distributor_stock SET qty = qty - ? WHERE distributor_id = ? AND product_id = ?",
      [qty, distributorId, productId]
    );

    // Activity log
    const [[distributor]] = await connection.query("SELECT name FROM distributors WHERE id = ?", [distributorId]);
    const [[product]] = await connection.query("SELECT name FROM products WHERE id = ?", [productId]);
    await connection.query(
      "INSERT INTO activity_logs (source, description) VALUES (?, ?)",
      [distributor.name, `Sold ${qty} units of ${product.name}`]
    );

    res.json({ success: true, message: 'Sale recorded' });
  } catch (err) {
    console.error("❌ Record Sales Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// Distributor Sales History - GET
app.get('/api/distributor/sales', async (req, res) => {
  const distributorId = req.query.distributorId;
  if (!distributorId) return res.status(400).json({ error: "Missing distributorId" });

  try {
    const [rows] = await connection.query(`
      SELECT s.id AS id, s.qty, s.date AS date, p.name AS productName
      FROM sales s
      JOIN products p ON s.product_id = p.id
      WHERE s.distributor_id = ?
      ORDER BY s.date DESC
    `, [distributorId]);

    res.json({ success: true, sales: rows });
  } catch (err) {
    console.error("❌ Distributor Sales History Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// Activity log - POST
app.post('/api/activity-log', async (req, res) => {
  const { source, description } = req.body;
  if (!source || !description) return res.status(400).json({ error: "Missing source or description" });

  try {
    await connection.query(
      "INSERT INTO activity_logs (source, description) VALUES (?, ?)",
      [source, description]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("❌ Activity Log Error:", err.message);
    res.status(500).json({ error: "Failed to log activity" });
  }
});

// ✅ Admin dashboard summary
app.get('/api/admin/summary', async (req, res) => {
  try {
    const [[productCount]] = await connection.query('SELECT COUNT(*) AS totalProducts FROM products');
    const [[warehouseCount]] = await connection.query('SELECT COUNT(*) AS totalWarehouses FROM warehouses');
    const [[distributorCount]] = await connection.query('SELECT COUNT(*) AS totalDistributors FROM distributors');
    const [[salesCount]] = await connection.query('SELECT COUNT(*) AS totalSales FROM sales');
    const [[orderCount]] = await connection.query('SELECT COUNT(*) AS totalOrders FROM incoming_orders');

    res.json({
  totalProducts: productCount.totalProducts,
  totalWarehouses: warehouseCount.totalWarehouses,
  totalDistributors: distributorCount.totalDistributors,
  totalSales: salesCount.totalSales,
  totalOrders: orderCount.totalOrders
});

  } catch (error) {
    console.error("❌ Admin Summary Error:", error.message);
    res.status(500).json({ error: "Server error while fetching summary" });
  }
});

// ✅ Admin distributor sales summary
app.get("/api/admin/distributor-sales", async (req, res) => {
  try {
    const [rows] = await connection.query(`
      SELECT d.name AS distributor, p.name AS product, SUM(s.qty) AS totalSold
      FROM sales s
      JOIN distributors d ON s.distributor_id = d.id
      JOIN products p ON s.product_id = p.id
      GROUP BY s.distributor_id, s.product_id
      ORDER BY totalSold DESC
    `);
    res.json({ success: true, sales: rows });
  } catch (err) {
    console.error("❌ Distributor Sales Error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});
// ✅ Default route
app.get('/', (req, res) => {
  res.send('✅ Millet Inventory Backend Running Successfully!');
});

app.get('/api/healthcheck', (req, res) => {
  res.json({ status: 'ok' });
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
