import { useState } from "react";
import { Key, Plus, RefreshCw, Shield, Copy, Eye, EyeOff, Download, Trash2, Clock, AlertTriangle, CheckCircle2 } from "lucide-react";
import { Header } from "../components/layout/Header";
import { Button } from "../components/ui/button";
import { KeyStatusBadge } from "../components/shared/KeyStatusBadge";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../components/ui/dialog";
import { cn } from "../lib/utils.js";
import { useKeys } from "../hooks/useKeys";
import { useAuth } from "../context/AuthContext";
import { generateIdentityKeyPair, storePrivateKeyEncrypted, exportPublicKey, deleteIdentityKey, loadPrivateKey, hasIdentityKey } from "../crypto/identityKeys";
import { rotateIdentityKeys } from "../crypto/keyRotation";
import api from "../services/api";
import { toast } from "../hooks/use-toast";
import { formatFileTimestamp } from "../utils/formatTime";
import { Skeleton } from "../components/ui/skeleton";

export default function Keys() {
  const { user } = useAuth();
  const [showFingerprint, setShowFingerprint] = useState({});
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRotating, setIsRotating] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [showPasswordDialog, setShowPasswordDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [actionType, setActionType] = useState(null); // 'generate' | 'rotate'
  const [targetKeyId, setTargetKeyId] = useState(null);
  const { keys, loading, error, refetch } = useKeys();

  const toggleFingerprint = (id) => {
    setShowFingerprint((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyFingerprint = async (fingerprint) => {
    try {
      await navigator.clipboard.writeText(fingerprint);
      toast({
        title: "Copied",
        description: "Fingerprint copied to clipboard",
      });
    } catch (err) {
      toast({
        title: "Error",
        description: "Failed to copy fingerprint",
        variant: "destructive",
      });
    }
  };

  const handleExportKey = async (key) => {
    try {
      if (!key.publicKeyJWK) {
        toast({
          title: "Error",
          description: "Public key not available for export",
          variant: "destructive",
        });
        return;
      }

      const keyData = {
        kty: key.publicKeyJWK.kty,
        crv: key.publicKeyJWK.crv,
        x: key.publicKeyJWK.x,
        y: key.publicKeyJWK.y,
        key_ops: key.publicKeyJWK.key_ops,
        ext: key.publicKeyJWK.ext,
      };

      const blob = new Blob([JSON.stringify(keyData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `identity-key-${key.id}-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast({
        title: "Exported",
        description: "Public key exported successfully",
      });
    } catch (err) {
      console.error('Failed to export key:', err);
      toast({
        title: "Error",
        description: "Failed to export key",
        variant: "destructive",
      });
    }
  };

  const handleGenerateKey = () => {
    setActionType('generate');
    setShowPasswordDialog(true);
  };

  const handleRotateKey = (keyId) => {
    setActionType('rotate');
    setTargetKeyId(keyId);
    setShowPasswordDialog(true);
  };

  const handleDeleteKey = (keyId) => {
    setTargetKeyId(keyId);
    setShowDeleteDialog(true);
  };

  const validatePassword = async (passwordToValidate) => {
    if (!user?.id) {
      throw new Error('User not authenticated');
    }

    // Check if key exists
    const keyExists = await hasIdentityKey(user.id);
    
    if (!keyExists) {
      // No existing key, password validation not needed for generation
      // But we should still verify it's a valid password format
      if (!passwordToValidate || passwordToValidate.length < 8) {
        throw new Error('Password must be at least 8 characters long');
      }
      return true;
    }

    // Try to decrypt existing key to validate password
    try {
      await loadPrivateKey(user.id, passwordToValidate);
      return true; // Password is correct
    } catch (err) {
      if (err.message.includes('decrypt') || err.message.includes('password') || err.message.includes('Invalid')) {
        throw new Error('Incorrect password. Please enter your account password.');
      }
      throw err; // Re-throw other errors
    }
  };

  const performKeyAction = async () => {
    if (!password || !user?.id) {
      toast({
        title: "Error",
        description: "Password is required",
        variant: "destructive",
      });
      return;
    }

    try {
      // Validate password first
      await validatePassword(password);

      if (actionType === 'generate') {
        setIsGenerating(true);
        
        // Check if key already exists
        const keyExists = await hasIdentityKey(user.id);
        if (keyExists) {
          throw new Error('Identity key already exists. Use "Rotate" to generate a new one.');
        }
        
        // Generate new identity key pair
        const { privateKey, publicKey } = await generateIdentityKeyPair();
        
        // Store private key encrypted
        await storePrivateKeyEncrypted(user.id, privateKey, password);
        
        // Export and upload public key
        const publicKeyJWK = await exportPublicKey(publicKey);
        try {
          const uploadResponse = await api.post('/keys/upload', { publicIdentityKeyJWK: publicKeyJWK });
          if (uploadResponse.data.success) {
            console.log('✓ Public key uploaded successfully');
          }
        } catch (uploadErr) {
          // 409 Conflict means key already exists - this is expected for updates
          if (uploadErr.response?.status === 409) {
            // Try to understand the error
            const errorMsg = uploadErr.response?.data?.message || uploadErr.response?.data?.error;
            if (errorMsg?.includes('integrity')) {
              throw new Error('Key integrity violation detected. Please contact support.');
            }
            // Otherwise, it's just an update - continue
            console.log('Key updated on server');
          } else {
            throw new Error(uploadErr.response?.data?.message || 'Failed to upload public key to server');
          }
        }
        
        toast({
          title: "Success",
          description: "Identity key pair generated successfully",
        });
        
        // Refresh keys list
        await refetch();
      } else if (actionType === 'rotate') {
        setIsRotating(true);
        
        // Rotate identity keys (this will validate password internally)
        const { publicKeyJWK } = await rotateIdentityKeys(user.id, password);
        
        // Upload new public key
        try {
          const uploadResponse = await api.post('/keys/upload', { publicIdentityKeyJWK: publicKeyJWK });
          if (uploadResponse.data.success) {
            console.log('✓ Public key rotated and uploaded successfully');
          }
        } catch (uploadErr) {
          // 409 Conflict means key already exists - this is expected for updates
          if (uploadErr.response?.status === 409) {
            // Check if it's an integrity violation
            const errorMsg = uploadErr.response?.data?.message || uploadErr.response?.data?.error;
            if (errorMsg?.includes('integrity')) {
              throw new Error('Key integrity violation detected. Please contact support.');
            }
            // Otherwise, it's just an update - continue
            console.log('Key updated on server');
          } else {
            throw new Error(uploadErr.response?.data?.message || 'Failed to upload rotated public key to server');
          }
        }
        
        toast({
          title: "Success",
          description: "Identity keys rotated successfully. All existing sessions will need to re-establish keys.",
        });
        
        // Refresh keys list
        await refetch();
      }
      
      setShowPasswordDialog(false);
      setPassword('');
    } catch (err) {
      console.error('Key operation failed:', err);
      const errorMessage = err.message || "Failed to perform key operation";
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
      setIsRotating(false);
    }
  };

  const performDeleteKey = async () => {
    if (!user?.id) return;

    setIsDeleting(true);
    try {
      // Delete from IndexedDB
      await deleteIdentityKey(user.id);
      
      // Optionally delete from server (if endpoint exists)
      try {
        // Note: There's no delete endpoint, but we could add one
        // For now, just delete locally
      } catch (err) {
        console.warn('Failed to delete key from server:', err);
      }
      
      toast({
        title: "Deleted",
        description: "Identity key deleted. You'll need to generate a new key to use encrypted messaging.",
        variant: "destructive",
      });
      
      setShowDeleteDialog(false);
      setTargetKeyId(null);
      
      // Refresh keys list
      await refetch();
    } catch (err) {
      console.error('Failed to delete key:', err);
      toast({
        title: "Error",
        description: err.message || "Failed to delete key",
        variant: "destructive",
      });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="min-h-screen">
      <Header title="Key Management" showMenu />

      <div className="p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Key Generation */}
        <div className="p-6 rounded-xl bg-gradient-to-br from-primary/10 via-card to-card border border-primary/20">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 rounded-2xl gradient-primary flex items-center justify-center glow-primary">
                <Key className="w-7 h-7 text-primary-foreground" />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-foreground">Generate New Key Pair</h2>
                <p className="text-sm text-muted-foreground mt-0.5">
                  Create a new ECC P-256 identity key for signing ephemeral keys
                </p>
              </div>
            </div>
            <Button 
              onClick={handleGenerateKey} 
              disabled={isGenerating || keys.length > 0} 
              className="w-full sm:w-auto"
            >
              {isGenerating ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4 mr-2" />
                  Generate Key
                </>
              )}
            </Button>
            {keys.length > 0 && (
              <p className="text-xs text-muted-foreground mt-2">
                You already have an identity key. Use "Rotate" to generate a new one.
              </p>
            )}
          </div>
        </div>

        {/* Security Notice */}
        <div className="p-4 rounded-xl bg-success/5 border border-success/20">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-success flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-foreground">Keys are stored securely</p>
              <p className="text-xs text-muted-foreground mt-1">
                All private keys are encrypted with your master password and never leave your device.
              </p>
            </div>
          </div>
        </div>

        {/* Keys List */}
        <div className="space-y-6">
          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="p-4 rounded-xl bg-card border border-border">
                  <Skeleton className="h-5 w-3/4 mb-2" />
                  <Skeleton className="h-4 w-full mb-1" />
                  <Skeleton className="h-4 w-2/3" />
                </div>
              ))}
            </div>
          ) : error ? (
            <div className="text-center py-12">
              <p className="text-destructive mb-2">Error loading keys: {error}</p>
              <Button variant="outline" size="sm" onClick={refetch}>
                Retry
              </Button>
            </div>
          ) : (
            <>
              {/* Identity Keys Section */}
              {keys.filter(k => k.category === 'identity').length > 0 && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <Shield className="w-5 h-5 text-primary" />
                    <h3 className="text-lg font-semibold text-foreground">Identity Keys</h3>
                    <span className="text-sm text-muted-foreground">
                      ({keys.filter(k => k.category === 'identity').length})
                    </span>
                  </div>
                  <div className="space-y-3">
                    {keys.filter(k => k.category === 'identity').map((key, i) => (
                      <div
                        key={key.id}
                        className={cn(
                          "p-4 rounded-xl bg-card border border-border hover:border-primary/30 transition-all duration-200 animate-fade-in",
                          key.status === "expired" && "opacity-60"
                        )}
                        style={{ animationDelay: `${i * 50}ms` }}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                          <div className="flex items-start gap-4">
                            <div className={cn(
                              "w-12 h-12 rounded-xl flex items-center justify-center",
                              key.status === "active" && "bg-success/10",
                              key.status === "expiring" && "bg-warning/10",
                              key.status === "expired" && "bg-destructive/10"
                            )}>
                              <Key className={cn(
                                "w-6 h-6",
                                key.status === "active" && "text-success",
                                key.status === "expiring" && "text-warning",
                                key.status === "expired" && "text-destructive"
                              )} />
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <h4 className="font-medium text-foreground">{key.name}</h4>
                                <KeyStatusBadge status={key.status} />
                              </div>
                              <p className="text-sm text-muted-foreground mt-1">
                                {key.keyType || key.type} • {key.expiresAt}
                              </p>
                              <div className="flex items-center gap-2 mt-2 flex-wrap">
                                <code className="text-xs font-mono text-muted-foreground bg-muted px-2 py-1 rounded">
                                  {showFingerprint[key.id] ? key.fingerprint : "•••• •••• •••• •••• ••••"}
                                </code>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  onClick={() => toggleFingerprint(key.id)}
                                  title={showFingerprint[key.id] ? "Hide fingerprint" : "Show fingerprint"}
                                >
                                  {showFingerprint[key.id] ? (
                                    <EyeOff className="w-3.5 h-3.5" />
                                  ) : (
                                    <Eye className="w-3.5 h-3.5" />
                                  )}
                                </Button>
                                <Button 
                                  variant="ghost" 
                                  size="icon-sm"
                                  onClick={() => handleCopyFingerprint(key.fingerprint)}
                                  title="Copy fingerprint"
                                >
                                  <Copy className="w-3.5 h-3.5" />
                                </Button>
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 sm:flex-shrink-0">
                            {key.status !== "expired" && (
                              <>
                                <Button 
                                  variant="secondary" 
                                  size="sm"
                                  onClick={() => handleRotateKey(key.id)}
                                  disabled={isRotating}
                                >
                                  <RefreshCw className={cn("w-3.5 h-3.5 mr-1.5", isRotating && "animate-spin")} />
                                  Rotate
                                </Button>
                                <Button 
                                  variant="secondary" 
                                  size="sm"
                                  onClick={() => handleExportKey(key)}
                                >
                                  <Download className="w-3.5 h-3.5 mr-1.5" />
                                  Export
                                </Button>
                              </>
                            )}
                            <Button 
                              variant="ghost" 
                              size="icon-sm" 
                              className="text-destructive hover:text-destructive"
                              onClick={() => handleDeleteKey(key.id)}
                              disabled={isDeleting}
                              title="Delete key"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>

                        <div className="flex items-center gap-4 mt-3 pt-3 border-t border-border text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3.5 h-3.5" />
                            Created {formatFileTimestamp(key.createdAt)}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Session Keys Section */}
              {keys.filter(k => k.category === 'session').length > 0 && (
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <Key className="w-5 h-5 text-primary" />
                    <h3 className="text-lg font-semibold text-foreground">Session Keys</h3>
                    <span className="text-sm text-muted-foreground">
                      ({keys.filter(k => k.category === 'session').length})
                    </span>
                  </div>
                  <div className="space-y-3">
                    {keys.filter(k => k.category === 'session').map((key, i) => (
                      <div
                        key={key.id}
                        className={cn(
                          "p-4 rounded-xl bg-card border border-border hover:border-primary/30 transition-all duration-200 animate-fade-in",
                          key.status === "expired" && "opacity-60"
                        )}
                        style={{ animationDelay: `${i * 50}ms` }}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                          <div className="flex items-start gap-4">
                            <div className={cn(
                              "w-12 h-12 rounded-xl flex items-center justify-center",
                              key.status === "active" && "bg-primary/10",
                              key.status === "expiring" && "bg-warning/10",
                              key.status === "expired" && "bg-destructive/10"
                            )}>
                              <Key className={cn(
                                "w-6 h-6",
                                key.status === "active" && "text-primary",
                                key.status === "expiring" && "text-warning",
                                key.status === "expired" && "text-destructive"
                              )} />
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 flex-wrap">
                                <h4 className="font-medium text-foreground">{key.name}</h4>
                                <KeyStatusBadge status={key.status} />
                              </div>
                              <p className="text-sm text-muted-foreground mt-1">
                                {key.keyType || key.type} • {key.expiresAt}
                              </p>
                              {key.keyPurpose && (
                                <p className="text-xs text-muted-foreground mt-1 italic">
                                  {key.keyPurpose}
                                </p>
                              )}
                              {key.sessionId && (
                                <p className="text-xs text-muted-foreground mt-1">
                                  Session ID: <code className="bg-muted px-1 py-0.5 rounded">{key.sessionId.substring(0, 16)}...</code>
                                  {key.peerId && (
                                    <> • Peer: <code className="bg-muted px-1 py-0.5 rounded">{key.peerId.substring(0, 8)}...</code></>
                                  )}
                                </p>
                              )}
                              <div className="flex items-center gap-2 mt-2 flex-wrap">
                                <code className="text-xs font-mono text-muted-foreground bg-muted px-2 py-1 rounded">
                                  {showFingerprint[key.id] ? key.fingerprint : "•••• •••• •••• •••• ••••"}
                                </code>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  onClick={() => toggleFingerprint(key.id)}
                                  title={showFingerprint[key.id] ? "Hide fingerprint" : "Show fingerprint"}
                                >
                                  {showFingerprint[key.id] ? (
                                    <EyeOff className="w-3.5 h-3.5" />
                                  ) : (
                                    <Eye className="w-3.5 h-3.5" />
                                  )}
                                </Button>
                                <Button 
                                  variant="ghost" 
                                  size="icon-sm"
                                  onClick={() => handleCopyFingerprint(key.fingerprint)}
                                  title="Copy fingerprint"
                                >
                                  <Copy className="w-3.5 h-3.5" />
                                </Button>
                              </div>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-4 mt-3 pt-3 border-t border-border text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3.5 h-3.5" />
                            Created {formatFileTimestamp(key.createdAt)}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {!loading && !error && keys.length === 0 && (
            <div className="text-center py-12">
              <p className="text-muted-foreground">No keys found</p>
              <p className="text-sm text-muted-foreground mt-2">
                Generate a key pair during registration or create one manually.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Password Dialog for Generate/Rotate */}
      <Dialog open={showPasswordDialog} onOpenChange={setShowPasswordDialog}>
        <DialogContent className="sm:max-w-[450px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Key className="w-5 h-5" />
              {actionType === 'generate' ? 'Generate Identity Key' : 'Rotate Identity Key'}
            </DialogTitle>
            <DialogDescription>
              {actionType === 'generate' 
                ? 'Enter your password to generate a new identity key pair.'
                : 'Enter your password to rotate your identity key.'}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-3 py-2">
            <div className="p-3 rounded-lg bg-primary/5 border border-primary/20">
              <p className="text-sm font-medium text-foreground mb-1">What are Identity Keys?</p>
              <p className="text-xs text-muted-foreground">
                Identity keys are long-term cryptographic keys (ECC P-256) used to:
              </p>
              <ul className="text-xs text-muted-foreground mt-1 ml-4 list-disc space-y-0.5">
                <li>Sign ephemeral keys during key exchange to prevent MITM attacks</li>
                <li>Verify your identity in secure communications</li>
                <li>Provide non-repudiation (proof of message origin)</li>
              </ul>
            </div>
            {actionType === 'rotate' && (
              <div className="p-3 rounded-lg bg-warning/5 border border-warning/20">
                <p className="text-sm font-medium text-foreground mb-1">Why Rotate Keys?</p>
                <ul className="text-xs text-muted-foreground mt-1 ml-4 list-disc space-y-0.5">
                  <li>Enhanced security after potential compromise</li>
                  <li>Regular key rotation (recommended every 90 days)</li>
                  <li>Recovery from suspected key exposure</li>
                  <li>Note: Existing encrypted sessions will need to re-establish keys</li>
                </ul>
              </div>
            )}
          </div>
          
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="keyPassword">Your Password</Label>
              <div className="relative">
                <Input
                  id="keyPassword"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your account password"
                  className="pr-10"
                  autoComplete="off"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && password) {
                      performKeyAction();
                    }
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-xs text-muted-foreground">
                Your password is used to encrypt the private key. It is never sent to the server.
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowPasswordDialog(false);
                setPassword('');
                setActionType(null);
              }}
              disabled={isGenerating || isRotating}
            >
              Cancel
            </Button>
            <Button
              onClick={performKeyAction}
              disabled={!password || isGenerating || isRotating}
            >
              {(isGenerating || isRotating) ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  {actionType === 'generate' ? 'Generating...' : 'Rotating...'}
                </>
              ) : (
                actionType === 'generate' ? 'Generate Key' : 'Rotate Key'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Key Confirmation Dialog */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="w-5 h-5" />
              Delete Identity Key
            </DialogTitle>
            <DialogDescription>
              This action cannot be undone. Deleting your identity key will prevent you from establishing new encrypted sessions.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-3 py-2">
            <div>
              <p className="text-sm font-medium text-foreground mb-2">
                Deleting your identity key will prevent you from:
              </p>
              <ul className="list-disc list-inside text-sm space-y-1 text-muted-foreground ml-2">
                <li>Establishing new encrypted sessions</li>
                <li>Signing ephemeral keys for key exchange</li>
                <li>Verifying your identity in secure communications</li>
              </ul>
            </div>
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
              <p className="text-sm font-medium text-destructive">
                ⚠️ Warning: You'll need to generate a new key to use encrypted messaging again.
              </p>
            </div>
          </div>
          
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              variant="outline"
              onClick={() => {
                setShowDeleteDialog(false);
                setTargetKeyId(null);
              }}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={performDeleteKey}
              disabled={isDeleting}
            >
              {isDeleting ? (
                <>
                  <div className="w-4 h-4 border-2 border-destructive-foreground/30 border-t-destructive-foreground rounded-full animate-spin mr-2" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="w-4 h-4 mr-2" />
                  Delete Key
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

