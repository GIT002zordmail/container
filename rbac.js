// Role-Based Access Control Module
class RBACManager {
  constructor() {
    this.roles = new Map();
    this.permissions = new Map();
    this.userRoles = new Map();
  }

  assignRole(user, role) {
    if (!this.userRoles.has(user)) {
      this.userRoles.set(user, []);
    }
    this.userRoles.get(user).push(role);
  }

  canAccess(user, resource) {
    const userRole = this.userRoles.get(user) || [];
    
    // Admin can access everything
    if (userRole.includes('admin')) {
      return true;
    }

    // Check specific permissions
    const perm = this.permissions.get(resource) || [];
    return perm.some(role => userRole.includes(role));
  }
}

module.exports = { RBACManager };
