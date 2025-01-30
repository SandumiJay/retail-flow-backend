const express = require("express"); // Importing the Express framework for building web applications
const cors = require("cors"); // Importing CORS middleware for enabling Cross-Origin Resource Sharing
const mysql = require("mysql2/promise"); // Importing MySQL library for database interactions with promises
const bcrypt = require("bcryptjs"); // Updated to use bcryptjs for password hashing
const bodyParser = require("body-parser"); // Middleware for parsing request bodies
const jwt = require("jsonwebtoken"); // Library for generating and verifying JSON Web Tokens
const dotenv = require("dotenv"); // Module for loading environment variables from a .env file
const multer = require("multer"); // Middleware for handling file uploads
const { v4: uuidv4 } = require("uuid"); // Function for generating unique identifiers
const fs = require("fs"); // File system module for file operations
const path = require("path"); // Module for handling file and directory paths
const { fileURLToPath } = require("url"); // Function for converting file URLs to paths
const { console } = require("inspector"); // Inspector console for debugging
const SSHDBConnection = require("./db.cjs"); // Importing the database connection module
const { saveSessionData, getSessionData } = require("./utils.cjs"); // Importing session management functions

dotenv.config(); // Load environment variables from a .env file

const app = express(); // Create an instance of the Express application
const port = 3001; // Define the port for the server

// Middleware setup
app.use(cors()); // Enable CORS for all routes
app.use(bodyParser.json()); // Parse JSON request bodies

// API endpoint to test server functionality
app.get("/api/hello", (req, res) => {
    res.json({ message: "Hello from the backend!" }); // Respond with a greeting message
});

// Serve static files from the uploads directory
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Create new user in the database
const createNewUser = async (username, password, email, role) => {
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Establish DB connection
    const db = await SSHDBConnection;

    // Retrieve role ID
    const [roleResult] = await db.query("SELECT id FROM userroles WHERE role = ?", [role]);
    const roleId = roleResult[0]?.id; // Safely access the ID

    if (!roleId) {
      throw new Error(`Role "${role}" does not exist.`); // Error if role does not exist
    }

    // Insert user into the database
    const [result] = await db.query(
      "INSERT INTO users (username, password, email, role, roleid) VALUES (?, ?, ?, ?, ?)",
      [username, hashedPassword, email, role, roleId]
    );

    return result.insertId; // Return the ID of the newly created user
  } catch (error) {
    throw new Error(`Failed to create user: ${error.message +"    " +role}`); // Error handling
  }
};

// API endpoint to create a new user
app.post("/api/create-user", async (req, res) => {
  const { username, password, email, role } = req.body;

  try {
    // Validate input fields
    if (!username || !password || !email || !role) {
      return res.status(400).json({ message: "All fields are required." }); // Error if fields are missing
    }

    // Create the new user
    const userId = await createNewUser(username, password, email, role);
    res.status(201).json({ message: "User created successfully", id: userId }); // Success response
  } catch (error) {
    console.error("Error creating user:", error.message); // Log error
    res.status(500).json({ message: error.message }); // Error response
  }
});

// API endpoint to update user information
app.put("/api/update-user/:id", async (req, res) => {
  try {
    const { id } = req.params; // Extract user ID from URL params
    const { username, email, password, role } = req.body;

    if (!id || !username || !email || !role) {
      return res.status(400).json({
        message: "ID, username, email, and role are required to update a user.",
      }); // Error if fields are missing
    }

    const pool = await SSHDBConnection;

    if (password) {
      // Hash the password if provided
      const hashedPassword = await bcrypt.hash(password, 10);
      const updateQuery =
        "UPDATE users SET username = ?, email = ?, password = ?, role = ? WHERE id = ?";
      await pool.query(updateQuery, [username, email, hashedPassword, role, id]);
    } else {
      // Update without the password
      const updateQuery =
        "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?";
      await pool.query(updateQuery, [username, email, role, id]);
    }

    res.status(200).json({ message: "User updated successfully." }); // Success response
  } catch (error) {
    console.error("Error updating user:", error); // Log error
    res.status(500).json({
      message: "An error occurred while updating the user.",
      error: error.message,
    }); // Error response
  }
});

// API endpoint to delete a user
app.delete("/api/delete-user/:id", async (req, res) => {
  try {
    const { id } = req.params; // Extract the user ID from the route parameter

    if (!id) {
      return res.status(400).json({ message: "User ID is required." }); // Error if ID is missing
    }

    const pool = await SSHDBConnection;

    // Perform the delete operation
    const result = await pool.query("DELETE FROM users WHERE id = ?", [id]);

    if (result.affectedRows === 0) {
      // If no rows were affected, the ID does not exist
      return res.status(404).json({ message: "User not found." }); // Error if user not found
    }

    res.status(200).json({ message: "User deleted successfully." }); // Success response
  } catch (error) {
    console.error("Error deleting user:", error); // Log error
    res.status(500).json({
      message: "An error occurred while deleting the user.",
      error: error.message,
    }); // Error response
  }
});

// API endpoint to update user status
app.put("/api/update-user-status/:id", async (req, res) => {
  try {
    const { id } = req.params; // Extract user ID from URL params
    const { status } = req.body;

    if (!id ) {
      return res.status(400).json({
        message: "ID is required to update a user.",
      }); // Error if ID is missing
    }

    const pool = await SSHDBConnection;

    const updateQuery =
        "UPDATE users SET status = ? WHERE id = ?";
      await pool.query(updateQuery, [status, id]);
   

    res.status(200).json({ message: "User status updated successfully." }); // Success response
  } catch (error) {
    console.error("Error updating user:", error); // Log error
    res.status(500).json({
      message: "An error occurred while updating the user.",
      error: error.message,
    }); // Error response
  }
});

// API endpoint for user login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const db = await SSHDBConnection; 
    const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" }); // Error if username not found
    }

    const user = rows[0];
    saveSessionData('role',user.role) // Save user role in session

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid username or password" }); // Error if password does not match
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || "default_secret", // Use environment variable
      {
        expiresIn: "1h", // Token expiration time
      }
    );

    res.json({ message: "Login successful", token }); // Success response with token
  } catch (error) {
    res.status(500).json({ message: "Internal server error" + error }); // Error response
  }
});

// API endpoint to get user role from session
app.get('/get-the-role', (req, res) => {
  const role = getSessionData('role');

  if (!role) {
    return res.status(404).json({ message: 'Role not found' }); // Error if role not found
  }

  res.status(200).json({ role }); // Success response with role
});

// API endpoint to create a new product category
app.post("/api/create-product-category", async (req, res) => {
  const { category } = req.body;
  try {
    console.log("req.body:", req.body);
    console.log("category:", category);
    if (!category) {
      return res.status(400).json({ message: "Category is required" }); // Error if category is missing
    }
    const pool = await SSHDBConnection; 
    const [result] = await pool.query(
      "INSERT INTO productcategories (Category, Status) VALUES (?, ?)",
      [category, 1] // Assuming status is 1 (active) by default
    );
    res.status(201).json({
      message: "Category created successfully",
      category: {
        id: result.insertId, // MySQL returns the inserted row ID
        category,
        status: 1,
      },
    }); // Success response
  } catch (error) {
    res.status(500).json({ message: "Internal server error" }); // Error response
  }
});

// API endpoint to get all product categories
app.get("/api/get-product-categories", async (req, res) => {
  try {
    // Query the database for all unique product categories
    const pool = await SSHDBConnection; 
    const [categories] = await pool.query(
      "SELECT DISTINCT id,Category,Status FROM productcategories group by id,Category,Status"
    );
    console.log(categories);
    // Check if categories are found
    if (categories.length === 0) {
      return res.status(404).json({ message: "No categories found" }); // Error if no categories found
    }

    // Return the list of categories in the response
    res.status(200).json({
      success: true,
      data: categories,
    }); // Success response with categories
  } catch (error) {
    // Improved error logging with specific message
    console.error("Database query error while retrieving categories:", error);

    // Return a more informative error message
    res.status(500).json({
      success: false,
      message: "Failed to retrieve product categories. Please try again later.",
    }); // Error response
  }
});

// API endpoint to update a product category
app.put("/api/update-product-category", async (req, res) => {
  const { id, category } = req.body;
  try {
    console.log("req.body:", req.body);
    console.log("category:", category);
    if (!category) {
      return res.status(400).json({ message: "Category is required" }); // Error if category is missing
    }
    const pool = await SSHDBConnection; 
    await pool.query("UPDATE productcategories SET Category = ? WHERE id = ?", [
      category,
      id,
    ]);
    res.status(200).json({
      message: "Category updated successfully",
      category: {
        id,
        category,
        status: 1,
      },
    }); // Success response
  } catch (error) {
    res.status(500).json({ message: "Internal server error" }); // Error response
  }
});

// Setup multer for local storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Specify the folder to save the uploaded files
    const uploadDir = path.join(__dirname, "uploads");

    // Ensure the upload directory exists
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir); // Create the directory if it does not exist
    }

    cb(null, uploadDir); // Callback to set the destination
  },
  filename: (req, file, cb) => {
    // Create a unique filename for the uploaded file
    const uniqueName = `${uuidv4()}-${file.originalname}`;
    cb(null, uniqueName); // Callback to set the filename
  },
});

const upload = multer({ storage }); // Initialize multer with the storage configuration

// API endpoint to upload a product image
app.post(
  "/api/upload-product-image",
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" }); // Error if no file uploaded
      }

      const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${
        req.file.filename
      }`;
      res.status(200).json({ url: fileUrl }); // Success response with file URL
    } catch (error) {
      res.status(500).json({ message: "Error uploading file", error }); // Error response
    }
  }
);

// API endpoint to delete a product category
app.delete("/api/delete-product-category", async (req, res) => {
  try {
    const { id } = req.query; // Get the product category ID from the query parameters
    const pool = await SSHDBConnection; 
    await pool.query("DELETE FROM productcategories WHERE id = ?", [id]);
    res.status(200).json({ message: "Category deleted successfully" }); // Success response
  } catch (error) {
    console.log(error); // Log error
  }
});

// API endpoint to add a product (with an already provided image URL)
app.post("/api/add-product", async (req, res) => {
  try {
    // Extract product data from req.body
    const { name, category, quantity, cost, price, image, maxDiscount } = req.body;
    let dicountAllowed=0;

    // Input validation
    if (!name) {
      return res.status(400).json({ message: "Product name is required" }); // Error if product name is missing
    }
    if (!category) {
      return res.status(400).json({ message: "Category is required" }); // Error if category is missing
    }
    if (quantity === undefined || quantity === null) {
      return res.status(400).json({ message: "Quantity is required" }); // Error if quantity is missing
    }
    if (isNaN(quantity) || quantity < 0) {
      return res.status(400).json({ message: "Quantity must be a non-negative number" }); // Error if quantity is invalid
    }
    // if (price === undefined || price === null) {
    //   return res.status(400).json({ message: "Price is required" }); // Error if price is missing
    // }
    // if (isNaN(price) || price < 0) {
    //   return res.status(400).json({ message: "Price must be a non-negative number" }); // Error if price is invalid
    // }
    if (isNaN(maxDiscount) || maxDiscount < 0 || maxDiscount > 100) {
      return res.status(400).json({ message: "maxDiscount must be a non-negative number and in between 0 and 100" }); // Error if maxDiscount is invalid
    }

    if(0 < maxDiscount &&  maxDiscount < 100){
      dicountAllowed=1; // Set discount allowed if within range
    }

    // Generate SKU and insert product data into the database
    const sku = await generateEntryCode(1);
    const pool = await SSHDBConnection; 
    const [result] = await pool.query(
      "INSERT INTO products (sku, productName, category, intQty,cost, price, image,maxDiscount,dicountAllowed) VALUES (?, ?, ?, ?, ?,?, ?, ?,?)",
      [sku, name, category, quantity,cost, price, image,maxDiscount,dicountAllowed]
    );

    // Return success response with inserted product details
    res.status(201).json({
      message: "Product added successfully",
      product: {
        id: result.insertId, // MySQL returns the inserted row ID
        sku,
        name,
        category,
        quantity,
        cost,
        price,
        image,
        maxDiscount,
        dicountAllowed,
      },
    }); // Success response
  } catch (error) {
    // Log the error for debugging
    console.error("Error adding product:", error);
    // Handle any errors
    res.status(500).json({ message: "Error adding product", error: error.message }); // Error response
  }
});

// API endpoint to get all users
app.get("/api/get-users", upload.single("image"), async (req, res) => {
  try {
    const pool = await SSHDBConnection; 
    const [rows] = await pool.query("SELECT * FROM users");

    // Return the list of users in the response
    res.status(200).json({
      users: rows,
    }); // Success response with users
  } catch (error) {
    console.error("Error retrieving users:", error); // Log error
    res.status(500).json({ message: "Internal server error" }); // Error response
  }
});

// API endpoint to get all products
app.get("/api/get-products", async (req, res) => {
  try {
    // Query the database for all product categories
    const pool = await SSHDBConnection; 
    const [rows] = await pool.query(
      `SELECT 
      id,
      sku,
      productName,
      category,
      CAST(intQty AS SIGNED) AS intQty,
      CAST(cost AS DOUBLE) AS cost,
      CAST(price AS DOUBLE) AS price,
      image,
      maxDiscount,
      status,
      dicountAllowed
       FROM products  `
    );
    console.log(rows);
    // Return the list of categories in the response
    res.status(200).json(rows); // Success response with products
  } catch (error) {
    console.error("Error retrieving categories:", error); // Log error
    res.status(500).json({ message: "Internal server error" }); // Error response
  }
});

// API endpoint to delete a product
app.delete("/api/delete-product", async (req, res) => {
  try {
    const { id } = req.body;  // Get the product ID from the request body
    console.log("Deleting product with ID:", id);

    // Perform the deletion
    const pool = await SSHDBConnection; 
    await pool.query("DELETE FROM products WHERE id = ?", [id]);
    await pool.query("commit");

    res.status(200).json({ message: "Product deleted successfully", id }); // Success response
  } catch (error) {
    console.error("Error deleting product:", error); // Log error
    res.status(500).json({ message: "Internal server error" }); // Error response
  }
});

// API endpoint to update a product
app.put("/api/update-product", async (req, res) => {
  const { sku, name, category, quantity, price, cost, image, maxDiscount } = req.body;

  // Validate that required fields are present
  const missingFields = [];
  let dicountAllowed=0;

  // Check for missing required fields
  if (!sku) missingFields.push("sku");
  if (!name) missingFields.push("name");
  if (!category) missingFields.push("category");
  // if (!quantity) missingFields.push("quantity");
  // if (!price) missingFields.push("price");
  // if (!cost) missingFields.push("cost");
  // if (!maxDiscount) missingFields.push("maxDiscount");

  // If there are missing fields, return a detailed error message
  if (missingFields.length > 0) {
    return res.status(400).json({
      message: `Missing required fields: ${missingFields.join(", ")}`, // Error if fields are missing
    });
  }
 if (0<maxDiscount && maxDiscount<100){
  dicountAllowed =1; // Set discount allowed if within range
 }

  try {
    // Update the product in the database
    const updateQuery = `
      UPDATE products
      SET productName = ?, category = ?, intQty = ?, price = ?, cost = ?, image = ?, maxDiscount=?, dicountAllowed=?
      WHERE sku = ?
    `;

    // Assuming you're using MySQL or a similar relational database
    const db = await SSHDBConnection; 
    const result = await db.query(updateQuery, [
      name,
      category,
      quantity,
      price,
      cost,
      image || null, // Use the new image or keep the old one
      maxDiscount,
      dicountAllowed,
      sku,
    ]);

    // If no rows were affected, the SKU was not found
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Product not found." }); // Error if product not found
    }

    return res.status(200).json({ message: "Product updated successfully." }); // Success response
  } catch (error) {
    console.error("Error updating product:", error); // Log error
    return res
      .status(500)
      .json({ message: error }); // Error response
  }
});

// API endpoint to auto-update inventory
app.put("/api/auto-update-inventory", async (req, res) => {
  const { products } = req.body;
  console.log(products);

  // Validate that the products array is provided and is an array
  if (!Array.isArray(products) || products.length === 0) {
    return res.status(400).json({
      message: "Request must include an array of products with SKU and quantity." + Array.isArray(products), // Error if products array is invalid
    });
  }

  // Validate each product in the array for missing fields (SKU and quantity)
  const missingProducts = products
    .filter((product, index) => !product.sku || product.quantity == null)
    .map((product, index) => `Product at index ${index}`);

  if (missingProducts.length > 0) {
    return res.status(400).json({
      message: `Missing required fields in products: ${missingProducts.join(", ")}`, // Error if fields are missing
    });
  }

  try {
    // Process each product in the array and update the database
    for (const { sku, quantity } of products) {
      if (quantity <= 0) {
        // Optionally check if the quantity is valid (greater than zero)
        return res.status(400).json({
          message: "Quantity must be greater than zero for SKU: " + sku, // Error if quantity is invalid
        });
      }

      // SQL query to update the inventory based on SKU and quantity
      const updateQuery = `
        UPDATE products
        SET intQty = intQty - ?
        WHERE sku = ? AND intQty >= ?
      `;

      // Update the quantity in the database for each product
      const db = await SSHDBConnection; 
      const [result] = await db.query(updateQuery, [quantity, sku, quantity]);

      // Check if the SKU was found and the quantity was updated
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: `Product with SKU ${sku} not found or insufficient stock.` }); // Error if product not found
      }
    }

    // If all products were successfully updated
    return res.status(200).json({ message: "Products updated successfully." }); // Success response
  } catch (error) {
    console.error("Error updating products:", error); // Log error
    return res.status(500).json({ message: "An error occurred while updating products." }); // Error response
  }
});

// API endpoint to update supplier information
app.put("/api/update-supplier", async (req, res) => {
  try {
    const { code, name, email, phone, address, city, country } = req.body;
    const updateQuery = `update suppliers set name = ?, email = ?, phone = ?, address = ?, city = ?, country = ? where code = ?`;
    const pool = await SSHDBConnection; 
    const result = await pool.query(updateQuery, [
      name,
      email,
      phone,
      address,
      city,
      country,
      code,
    ]);
    res.status(200).json({ message: "Supplier updated successfully." }); // Success response
  } catch (error) {
    console.log(error); // Log error
  }
});

// API endpoint to update customer information
app.put("/api/update-customer", async (req, res) => {
  try {
    const { code, name, email, contact, address, city, country, status } = req.body;
    const updateQuery = `UPDATE customers SET name = ?, email = ?, contact = ?, address = ?, city = ?, country = ? WHERE code = ?`;
    const pool = await SSHDBConnection; 
    await pool.query(updateQuery, [
      name,
      email,
      contact,  // corrected from 'phone' to 'contact'
      address,
      city,
      country,
      code,
    ]);
    res.status(200).json({ message: "Customer updated successfully." }); // Success response
  } catch (error) {
    console.log(error); // Log error
    res.status(500).json({ message: "An error occurred while updating the customer." }); // Error response
  }
});

// API endpoint to delete a supplier
app.post("/api/delete-supplier", async (req, res) => {
  try {
    const { supplier } = req.body;
    console.log("cd");
    console.log(supplier);
    console.log(req.body);
    const pool = await SSHDBConnection; 
    await pool.query("DELETE FROM suppliers WHERE code = ?", [supplier.code]);
    res.status(200).json({ message: "Supplier deleted successfully." }); // Success response
  } catch (error) {
    console.log(error); // Log error
  }
});

// API endpoint to delete a customer
app.post("/api/delete-customer", async (req, res) => {
    try {
      const { customers } = req.body;  // Get the product ID from the request body
      console.log("Deleting Customer with ID:", customers.id);
  
      // Perform the deletion
      const pool = await SSHDBConnection; 
      await pool.query("Delete FROM customers where id  = ?", [customers.id]);
      await pool.query("commit");
  
      res.status(200).json({ message: customers.name + " Product deleted successfully"}); // Success response
    } catch (error) {
      console.error("Error deleting product:", error); // Log error
      res.status(500).json({ message: "Internal server error" }); // Error response
    }
});

// API endpoint to delete a purchase order
app.post("/api/delete-purchase-order", async (req, res) => {
  try {
    const { poCode } = req.body;  // Get purchase order code from URL parameters
    console.log(poCode)

    if (!poCode) {
      return res.status(400).json({ message: "Missing purchase order code (poCode)" }); // Error if poCode is missing
    }

    // Logging details for debugging
    console.log("Received purchase order code to delete: ", poCode);

    // Delete from related tables
    console.log("DELETE FROM purchaseorderdetails WHERE poCode = ", poCode);
    const pool = await SSHDBConnection; 
    await pool.query("DELETE FROM purchaseorderdetails WHERE poCode = ?", [poCode]);
    await pool.query("DELETE FROM purchaseorder WHERE purchaseOrderCode = ?", [poCode]);

    res.status(200).json({ message: "Purchase order and details deleted successfully." }); // Success response

  } catch (error) {
    console.error("Error deleting purchase order:", error); // Log error
    res.status(500).json({ message: "Error deleting purchase order" }); // Error response
  }
});

// API endpoint to add a supplier
app.post("/api/add-supplier", async (req, res) => {
  const { name, email, phone, address, city, country } = req.body;
  const missingFields = [];

  // Check each field and push missing fields to the array
  // if (!code) missingFields.push("code");
  if (!name) missingFields.push("name");
  // if (!email) missingFields.push("email");
  // if (!phone) missingFields.push("phone");
  // if (!address) missingFields.push("address");
  // if (!city) missingFields.push("city");
  // if (!country) missingFields.push("country");

  // If there are missing fields, return a detailed error message
  if (missingFields.length > 0) {
    return res.status(400).json({
      message: `Missing required fields: ${missingFields.join(", ")}`, // Error if fields are missing
    });
  }

  // Generate Entry Code
  let EntryCode;
  try {
    EntryCode = await generateEntryCode(2);  // Assuming this function exists
  } catch (error) {
    return res.status(500).json({ message: "Error generating entry code" }); // Error if entry code generation fails
  }

  try {
    const pool = await SSHDBConnection; 
    const [result] = await pool.query(
      "INSERT INTO suppliers (code, name, email, phone, address, city, country) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [EntryCode, name, email, phone, address, city, country]
    );

    // Return success response
    return res.status(200).json({
      message: "Supplier added successfully",
      supplierId: result.insertId, // Return the ID of the newly created supplier
    }); // Success response
  } catch (error) {
    console.error("Error adding supplier:", error); // Log error
    return res.status(500).json({
      message: "Error adding supplier",
      error: error.message,  // You can omit the detailed error message in production for security reasons
    }); // Error response
  }
});

// API endpoint to get all suppliers
app.get("/api/get-suppliers", async (req, res) => {
  try {
    const pool = await SSHDBConnection; 
    const [rows] = await pool.query("SELECT * FROM suppliers");
    res.status(200).json(rows); // Success response with suppliers
  } catch (error) {
    console.error("Error retrieving suppliers:", error); // Log error
  }
});

// API endpoint to add a customer
app.post("/api/add-customer", async (req, res) => {
  const { code, name, email, contact, address, city, country } = req.body;
  const missingFields = [];
  const EntryCode = await generateEntryCode(5);

  // Check each field and push missing fields to the array
  // if (!code) missingFields.push("code");
  if (!name) missingFields.push("name");
  // if (!contact) missingFields.push("contact");
  // if (!address) missingFields.push("address");
  // if (!city) missingFields.push("city");
  // if (!country) missingFields.push("country");

  // If there are missing fields, return a detailed error message
  if (missingFields.length > 0) {
    return res.status(400).json({
      message: `Missing required fields: ${missingFields.join(", ")}`, // Error if fields are missing
    });
  }
  try {
    const pool = await SSHDBConnection; 
    const [result] = await pool.query(
      "INSERT INTO customers (code, name, email, contact, address, city, country) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [EntryCode, name, email, contact, address, city, country]
    );

    res.status(200).json({
      message: "Customer added successfully",
      customer: result.insertId, // Return the ID of the newly created customer
    }); // Success response
  } catch (error) {
    console.error("Error adding customer:", error); // Log error
  }
});

// API endpoint to get all customers
app.get("/api/get-customers", async (req, res) => {
  try {
    const pool = await SSHDBConnection; 
    const [rows] = await pool.query("SELECT * FROM customers");
    res.status(200).json(rows); // Success response with customers
  } catch (error) {
    console.error("Error retrieving customers:", error); // Log error
  }
});

// API endpoint to update code format
app.post("/api/update-code-format", async (req, res) => {
  const { type, prefix, sample, length } = req.body;
  try {
    // await pool.query("UPDATE codeformats SET PreFix = ?,length=? WHERE Code = ?", [prefix, type]);
    const pool = await SSHDBConnection; 
    await pool.query(
      "UPDATE codeformats SET PreFix = ?, length = ?, Sample = ? WHERE Code = ?",
      [prefix, length, sample, type]
    );
    res.status(200).json({ message: "Code format updated successfully." }); // Success response
  } catch (error) {
    console.error("Error updating code format:", error); // Log error
    res
      .status(500)
      .json({ message: "An error occurred while updating the code format." }); // Error response
  }
});

// API endpoint to get all code formats
app.get("/api/get-code-formats", async (req, res) => {
  try {
    const pool = await SSHDBConnection; 
    const [rows] = await pool.query("SELECT * FROM codeformats");
    res.status(200).json(rows); // Success response with code formats
  } catch (error) {
    console.error("Error retrieving code formats:", error); // Log error
  }
});

// Function to generate a new entry code
const generateEntryCode = async (codeType) => {
  const pool = await SSHDBConnection; 
  const [rows] = await pool.query("SELECT * FROM codeformats WHERE Code = ?", [
    codeType,
  ]);

  const nextValue = rows[0].nextValue; // Get the next value for the code
  const preFix = rows[0].PreFix; // Get the prefix for the code
  const Length = rows[0].length; // Get the length for the code
  const newValue = nextValue + 1; // Increment the next value
  await pool.query("update codeformats SET nextValue=? where Code =? ", [
    newValue,
    codeType,
  ]);

   const codeSample = preFix + String(newValue).padStart(Length, "0"); // Generate the new entry code

  return codeSample; // Return the new entry code
};

// API endpoint to create a purchase order
app.post("/api/create-purchase-order", async (req, res) => {
  const { supplier, orderDetails, totalCost } = req.body;

  try {
    // Generate a unique code for the purchase order
    const EntryCode = await generateEntryCode(2);
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0'); // Month is 0-indexed
    const day = String(date.getDate()).padStart(2, '0');

    const qdate = `${year}-${month}-${day}`; // Format the date
    const pool = await SSHDBConnection; 

    // Insert the purchase order details into the 'purchaseorder' table
    const [result] = await pool.query(
      "INSERT INTO purchaseorder (purchaseOrderCode, SupplierCode, SupplierName, TotalCost, postDate, docDate) VALUES (?, ?, ?, ?, ?, ?)",
      [
        EntryCode,
        supplier.code,
        supplier.name,
        totalCost,
        qdate,
        qdate,
      ]
    );
    console.log("orderDetails:", orderDetails)
    // Check if orderDetails exist to insert them into the appropriate table
    if (orderDetails && orderDetails.length > 0) {
      //const purchaseOrderId = result.insertId; // Get the ID of the newly created purchase order

      const orderItems = orderDetails.map((item) => [
        EntryCode,
        item.sku,
        item.productName,
        item.quantity,
        item.cost,
      ]);
      const pool = await SSHDBConnection; 
      // Insert the order details into the 'purchaseorderdetails' table
      await pool.query(
        "INSERT INTO purchaseorderdetails (poCode, ProductCode, productName, qty, cost) VALUES ?",
        [orderItems]
      );
    }

    res.status(200).json({
      message: "Purchase order added successfully",
      purchaseOrderId: result.insertId, // Return the ID of the newly created purchase order
    }); // Success response
  } catch (error) {
    console.error("Error creating purchase order:", error); // Log error
    res
      .status(500)
      .json({ error: "An error occurred while creating the purchase order " + error }); // Error response
  }
});

// API endpoint to get all purchase orders
app.get("/api/get-purchase-orders", async (req, res) => {
  try {
    const pool = await SSHDBConnection; 
    const [rows] = await pool.query("SELECT * FROM purchaseorder  ");
    res.status(200).json(rows); // Success response with purchase orders
  } catch (error) {
    console.log(error); // Log error
  }
});

// API endpoint to save an invoice
app.post("/api/save-invoice", async (req, res) => {
  const { customer, invoice, cartItems } = req.body;
  const EntryCode = await generateEntryCode(6);
  try {
    // Establish a connection from the pool
    const connection = await SSHDBConnection; 

    // Start transaction
    await connection.beginTransaction();

    // Debugging: log the variables to ensure they are correctly formatted
    console.log('Customer:', customer);
    console.log('Invoice:', invoice);
    console.log('Cart Items:', cartItems);

    // Insert into the invoices table
    const [invoiceResult] = await connection.execute(
      `INSERT INTO sales_invoices (code, customer_id, post_date, due_date, payment_method, total_amount, discount_amount, net_total)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        EntryCode,
        customer.code,
        invoice.postDate,
        invoice.dueDate,
        invoice.paymentMethod,
        invoice.totalAmount,
        invoice.discountAmount,
        invoice.netTotal,
      ]
    );

    // Debugging: Ensure invoice insertion was successful
    console.log('Invoice inserted, result:', invoiceResult);

    // Insert cart items
    const cartItemPromises = cartItems.map((item) => {
      return connection.execute(
        `INSERT INTO cart_items (invoice_code, sku, name, quantity, price, discount)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          EntryCode, // Invoice ID is the EntryCode
          item.sku,
          item.name,
          item.quantity,
          item.price,
          item.discount || 0, // Ensure discount defaults to 0 if not provided
        ]
      );
    });

    // Wait for all cart items to be inserted
    await Promise.all(cartItemPromises);

    // Commit transaction
    await connection.commit();

    // Respond with success
    res.status(200).json({ message: "Invoice saved successfully!", invoiceCode: EntryCode }); // Success response
  } catch (error) {
    // Rollback transaction if there's an error
    // if (connection) await connection.rollback();
    console.error("Error saving invoice:", error); // Log error
    res.status(500).json({ message: "Failed to save invoice. " + error.message }); // Error response
  } 
});

// API endpoint to get purchase order details
app.get("/api/get-purchase-orders-details", async (req, res) => {
  try {
    const poCode = req.query.poCode;

    if (!poCode) {
      return res.status(400).json({ error: "poCode is required" }); // Error if poCode is missing
    }

    console.log("Executing query:", "SELECT * FROM purchaseorderdetails where poCode= ?", [poCode]);
    const pool = await SSHDBConnection; 

    const [rows] = await pool.query("SELECT * FROM purchaseorderdetails WHERE poCode = ?", [poCode]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "No purchase order found for the given poCode" }); // Error if no purchase order found
    }

    res.status(200).json(rows); // Success response with purchase order details
  } catch (error) {
    console.log(error); // Log error
    res.status(500).json({ error: "Internal Server Error " + error }); // Error response
  }
});

// API endpoint to get receipt entry code
app.post("/api/get-reciept-entry-code", async (req, res) => {
  try {
    const { codeType } = req.body;
    const pool = await SSHDBConnection; 
    const [rows] = await pool.query(
      "SELECT * FROM codeformats WHERE Code = ?",
      [codeType.codeType]
    );

    const nextValue = rows[0].nextValue; // Get the next value for the code
    const preFix = rows[0].PreFix; // Get the prefix for the code
    const Length = rows[0].length; // Get the length for the code
    const newValue = nextValue + 1; // Increment the next value
    await pool.query("update codeformats SET nextValue=? where Code =? ", [
      newValue,
      codeType,
    ]);
    const newEntryCode = generateEntryCode(preFix, Length, newValue); // Generate the new entry code
    res.status(200).json(newEntryCode); // Success response with new entry code
  } catch (error) {
    console.error("Error retrieving code formats:", error); // Log error
  }
});

app.get('/api/sales/by-date', async (req, res) => {
  const query = `
    SELECT 
      DATE(post_date) AS date, 
      SUM(net_total) AS total_net 
    FROM saysmulx_qtmp.sales_invoices 
    GROUP BY DATE(post_date)
    ORDER BY date;
  `;
  try {
    const pool = await SSHDBConnection; 
    const data = await pool.query(query);
    res.json({ data });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ error: 'An error occurred while processing your request.'+ error.message });
  }
});

app.get('/api/sales/by-month', async (req, res) => {
  const query = `
    SELECT 
      DATE_FORMAT(post_date, '%Y-%m') AS month, 
      SUM(net_total) AS total_net 
    FROM saysmulx_qtmp.sales_invoices 
    GROUP BY DATE_FORMAT(post_date, '%Y-%m')
    ORDER BY month;
  `;
  try {
    const pool = await SSHDBConnection; 
    const data = await pool.query(query);
    res.json({ data });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ error: 'An error occurred while processing your request.' + error.message });
  }
});


app.get('/api/sales/by-year', async (req, res) => {
  const query = `
    SELECT 
      YEAR(post_date) AS year, 
      SUM(net_total) AS total_net 
    FROM saysmulx_qtmp.sales_invoices 
    GROUP BY YEAR(post_date)
    ORDER BY year;
  `;
  try {
    const pool = await SSHDBConnection; 
    const data = await pool.query(query);
    res.json({ data });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ error: 'An error occurred while processing your request.' + error.message });
  }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`); // Log server start message
});
