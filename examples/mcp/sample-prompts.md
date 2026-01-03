# Sample AI Prompts for Data Generation

Use these prompts with your AI assistant to generate sample data in MongoDB through the sstart MCP proxy.

## Quick Start Prompt

For getting started quickly, use this simple prompt:

```
Create a simple e-commerce database in MongoDB with:
- Database name: "demo"
- Collection "products" with 20 products (name, price, category, stock)
- Collection "customers" with 10 customers (name, email, tier)
- Collection "orders" with 15 orders (customer_id, total, status, date)

Use realistic data with variety in prices ($10-$500) and categories (Electronics, Clothing, Books).
```

---

## E-Commerce Database

### Minimal Version (Quick Setup)

```
Create an e-commerce database in MongoDB:

Database: "demo"

Collection: "products" (20 documents)
- name: string
- description: string (50 words)
- price: number ($10-$500)
- category: string (Electronics, Clothing, Books, Home, Sports)
- stock: number (0-100)
- tags: array of strings
- created_at: date (last 6 months)

Collection: "customers" (10 documents)
- name: string
- email: string (unique)
- address: object (city, state, zip)
- tier: string (bronze, silver, gold)
- join_date: date (last year)

Collection: "orders" (15 documents)
- order_number: string (ORD-2024-XXX)
- customer_id: ObjectId (reference customers)
- items: array of objects (product_id, quantity, price)
- total: number
- status: string (pending, shipped, delivered)
- order_date: date (last 3 months)

Use realistic, varied data.
```

### Detailed Version (Rich Demo)

```
Create a comprehensive e-commerce system in MongoDB:

Database: "demo"

Collection: "products" (50 documents)
- sku: string (e.g., "LAPTOP-001")
- name: string
- description: string (100-150 words)
- price: number ($10-$3000)
- category: string (Electronics, Clothing, Books, Home, Sports)
- subcategory: string (relevant to category)
- stock: number (0-100)
- tags: array of strings (3-5 tags)
- specs: object (category-specific attributes)
- rating: number (1-5, with decimals)
- reviews_count: number
- created_at: date (last 12 months)

Collection: "customers" (25 documents)
- email: string (unique)
- name: string
- address: object (street, city, state, zip)
- tier: string (bronze, silver, gold, platinum)
- join_date: date (last 2 years)
- total_spent: number
- orders_count: number

Collection: "orders" (75 documents)
- order_number: string (ORD-2024-XXX)
- customer_id: ObjectId (reference customers)
- items: array of objects (product_id, sku, quantity, price)
- subtotal: number
- tax: number
- total: number
- status: string (pending, processing, shipped, delivered, cancelled)
- order_date: date (last 6 months)
- delivery_date: date (if delivered)
- shipping_address: object

Collection: "reviews" (100 documents)
- product_id: ObjectId (reference products)
- customer_id: ObjectId (reference customers)
- rating: number (1-5)
- title: string
- comment: string (50-200 words)
- helpful_votes: number (0-50)
- verified_purchase: boolean
- date: date (last 6 months)

Use realistic, varied data. Ensure referential integrity between collections.
Products should have varied prices, multiple categories. Orders should reference real customers and products.
```

---

## Blog Platform

```
Create a tech blog platform database:

Database: "demo"

Collection: "posts" (30 documents)
- title: string
- slug: string (URL-friendly)
- content: string (500-1000 words on tech topics: AI, Cloud, DevOps, Security)
- author_id: ObjectId (reference authors)
- tags: array (AI, Cloud, DevOps, Security, Kubernetes, Docker, etc.)
- views: number (100-10000)
- published_date: date (last year)
- status: string (draft, published, archived)
- featured: boolean
- excerpt: string (100 words)

Collection: "authors" (8 documents)
- name: string
- bio: string (100 words)
- email: string (unique)
- avatar_url: string (example URLs)
- social_links: object (twitter, github, linkedin)
- posts_count: number
- joined_date: date (last 2 years)

Collection: "comments" (80 documents)
- post_id: ObjectId (reference posts)
- author_name: string
- email: string
- content: string (50-200 words)
- likes: number (0-50)
- created_at: date
- status: string (approved, pending, spam)
- parent_id: ObjectId (for nested comments, can be null)

Generate realistic tech blog content about modern development topics.
Ensure posts reference real authors. Some comments should be replies to other comments.
```

---

## IoT Sensors

```
Create an IoT sensor monitoring database:

Database: "demo"

Collection: "devices" (15 documents)
- device_id: string (SENSOR-XXX)
- name: string
- type: string (temperature, humidity, motion, pressure, light)
- location: object (building, floor, room, coordinates)
- status: string (active, inactive, maintenance)
- last_seen: date (recent)
- installed_date: date (last year)

Collection: "readings" (200 documents)
- device_id: string (reference devices)
- timestamp: date (last 30 days, spread throughout)
- value: number (varies by device type - realistic ranges)
- unit: string (°C, %, psi, lux, etc.)
- quality: string (good, fair, poor)

Collection: "alerts" (25 documents)
- device_id: string (reference devices)
- type: string (warning, critical)
- message: string
- threshold_value: number
- actual_value: number
- created_at: date (last 30 days)
- resolved_at: date (or null for open alerts)
- resolved: boolean

Use realistic sensor values:
- Temperature: 15-35°C
- Humidity: 30-80%
- Pressure: 980-1020 psi
- Motion: 0 (no motion) or 1 (motion detected)
- Light: 0-1000 lux

Create patterns in data (e.g., temperature variations throughout the day).
```

---

## Simple Inventory

```
Create a warehouse inventory system:

Database: "demo"

Collection: "products" (30 documents)
- sku: string (e.g., "PROD-XXX")
- name: string
- quantity: number (0-500)
- location: string (Aisle-XX-Shelf-Y format)
- supplier_id: ObjectId (reference suppliers)
- cost_price: number
- sell_price: number
- reorder_point: number
- last_updated: date (recent)

Collection: "suppliers" (8 documents)
- name: string (company name)
- contact_person: string
- email: string
- phone: string
- address: object (street, city, state, zip)
- rating: number (1-5)
- products_supplied: number

Collection: "transactions" (50 documents)
- product_id: ObjectId (reference products)
- type: string (restock, sale, return, adjustment)
- quantity: number (positive for restock/return, negative for sale)
- cost: number
- date: date (last 3 months)
- notes: string
- operator: string (staff name)

Keep it simple but professional. Products should have varied quantities.
Transactions should show realistic inventory movement patterns.
```

---

## Tips for Best Results

1. **Be Specific**: The more details you provide, the better the generated data
2. **Request Relationships**: Ask AI to ensure referential integrity (e.g., orders reference real customers)
3. **Vary Data**: Request variety in values (prices, dates, statuses)
4. **Use Realistic Ranges**: Provide realistic value ranges for numbers and dates
5. **Check Results**: After generation, query the data to verify it meets your needs

## Example Follow-up Queries

After generating data, try these queries:

```
- "Show me all products priced between $100 and $500"
- "What's the total revenue by category?"
- "List the top 10 customers by total spending"
- "Show orders from the last 30 days"
- "Find products with stock below 10"
- "Calculate average order value"
- "Show the most reviewed products"
```
