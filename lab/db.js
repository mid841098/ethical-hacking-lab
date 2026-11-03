/**
 * Authorized Training Application - Mock Database & Seed Records
 * Track: Ethical Hacking - EdVyro Internship
 * Purpose: Safe, self-contained, in-memory datastore with intentional vulnerabilities
 *          for authorized laboratory testing only.
 * Hard Scope: Strictly local in-memory storage (RFC 1918 / Loopback only).
 */

const crypto = require('crypto');

class LabDatabase {
  constructor() {
    this.reset();
  }

  reset() {
    // Seed Users
    this.users = [
      {
        id: 1,
        username: 'alice_admin',
        email: 'alice@internal-lab.local',
        role: 'admin',
        passwordHash: crypto.createHash('sha256').update('AdminPass@2026!').digest('hex'),
        fullName: 'Alice Walker',
        phone: '+1-555-0101',
        balance: 15400.00,
        apiToken: 'tok_admin_9847bf29841ca9028',
        isSuperUser: true
      },
      {
        id: 2,
        username: 'bob_student',
        email: 'bob@internal-lab.local',
        role: 'user',
        passwordHash: crypto.createHash('sha256').update('BobStudent#123').digest('hex'),
        fullName: 'Bob Martinez',
        phone: '+1-555-0102',
        balance: 245.50,
        apiToken: 'tok_user_3857ca02981ef8471',
        isSuperUser: false
      },
      {
        id: 3,
        username: 'carol_auditor',
        email: 'carol@internal-lab.local',
        role: 'auditor',
        passwordHash: crypto.createHash('sha256').update('CarolAudit$789').digest('hex'),
        fullName: 'Carol Danvers',
        phone: '+1-555-0103',
        balance: 890.00,
        apiToken: 'tok_auditor_5521ab93847291',
        isSuperUser: false
      }
    ];

    // Seed Products / Inventory
    this.products = [
      { id: 101, name: 'OWASP Security Guide v4.2', category: 'Books', price: 29.99, isPublic: true, stock: 45, internalNotes: 'Public catalog item' },
      { id: 102, name: 'Hardware Security Key (FIDO2)', category: 'Hardware', price: 49.99, isPublic: true, stock: 120, internalNotes: 'Standard inventory' },
      { id: 103, name: 'Penetration Testing Field Manual', category: 'Books', price: 34.50, isPublic: true, stock: 15, internalNotes: 'Popular guide' },
      { id: 104, name: 'Internal Red-Team Assessment Toolkit [CONFIDENTIAL]', category: 'Restricted', price: 999.00, isPublic: false, stock: 2, internalNotes: 'RESTRICTED: Internal staff tool only. Flag: FLAG{sql_inj_unreleased_data_leak}' },
      { id: 105, name: 'Hardware RF Transceiver Kit', category: 'Hardware', price: 89.00, isPublic: true, stock: 8, internalNotes: 'Standard stock' }
    ];

    // Orders / Invoices (Used for IDOR demonstrations)
    this.orders = [
      { id: 5001, userId: 1, total: 1028.99, status: 'Completed', items: ['Internal Red-Team Assessment Toolkit', 'OWASP Security Guide'], shippingAddress: 'HQ Secure Operations Center, Suite 400' },
      { id: 5002, userId: 2, total: 29.99, status: 'Processing', items: ['OWASP Security Guide v4.2'], shippingAddress: '42 Student Way, Campus Dorms' },
      { id: 5003, userId: 3, total: 84.49, status: 'Shipped', items: ['Hardware Security Key', 'Penetration Testing Field Manual'], shippingAddress: '10 Audit Road, North Tower' }
    ];

    // Audit / Access Logs
    this.auditLogs = [];
  }

  logAccess(method, path, ip, status) {
    this.auditLogs.push({
      timestamp: new Date().toISOString(),
      method,
      path,
      ip,
      status
    });
  }
}

module.exports = new LabDatabase();
