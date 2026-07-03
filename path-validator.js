// Path Traversal Prevention Module
const path = require('path');
const fs = require('fs');

class PathValidator {
  validateFilePath(filename, baseDir) {
    // Remove null bytes
    if (filename.includes('\0')) {
      throw new Error('Null bytes in path');
    }

    // Prevent directory traversal
    if (filename.includes('..')) {
      throw new Error('Directory traversal detected');
    }

    const fullPath = path.join(baseDir, filename);
    const normalizedPath = path.normalize(fullPath);

    // Ensure the normalized path starts with baseDir
    if (!normalizedPath.startsWith(path.normalize(baseDir))) {
      throw new Error('Path outside base directory');
    }

    return normalizedPath;
  }

  isPathAllowed(filePath, allowedDirs) {
    const normalizedPath = path.normalize(filePath);

    for (const dir of allowedDirs) {
      const normalizedDir = path.normalize(dir);
      if (normalizedPath.startsWith(normalizedDir)) {
        return true;
      }
    }

    return false;
  }
}

module.exports = new PathValidator();
