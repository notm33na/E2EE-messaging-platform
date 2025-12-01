// Babel plugin to inject crypto global for ES modules
// This ensures that code using 'crypto' directly can access the Web Crypto API polyfill
module.exports = function() {
  return {
    visitor: {
      Program(path) {
        // Check if crypto is already declared in this scope
        const hasCryptoBinding = path.scope.hasBinding('crypto');
        const hasCryptoImport = path.node.body.some(
          node => node.type === 'ImportDeclaration' && 
          node.specifiers.some(s => s.local.name === 'crypto')
        );
        
        // Only inject if crypto is used but not declared/imported
        if (!hasCryptoBinding && !hasCryptoImport) {
          // Check if crypto is referenced in the code
          let cryptoUsed = false;
          path.traverse({
            Identifier(identifierPath) {
              if (identifierPath.node.name === 'crypto' && 
                  identifierPath.parent.type !== 'MemberExpression' &&
                  identifierPath.parent.type !== 'VariableDeclarator') {
                // Check if it's being used as a standalone identifier
                const parent = identifierPath.parent;
                if (parent.type === 'MemberExpression' && parent.object === identifierPath.node) {
                  cryptoUsed = true;
                }
              }
            }
          });
          
          // Inject crypto declaration at the top of the module
          if (cryptoUsed || path.scope.hasGlobal('crypto')) {
            const t = require('@babel/core').types;
            const cryptoDecl = t.variableDeclaration('const', [
              t.variableDeclarator(
                t.identifier('crypto'),
                t.logicalExpression(
                  '||',
                  t.memberExpression(t.identifier('globalThis'), t.identifier('crypto')),
                  t.logicalExpression(
                    '||',
                    t.memberExpression(t.identifier('global'), t.identifier('crypto')),
                    t.memberExpression(t.identifier('window'), t.identifier('crypto'))
                  )
                )
              )
            ]);
            path.unshiftContainer('body', cryptoDecl);
          }
        }
      }
    }
  };
};

