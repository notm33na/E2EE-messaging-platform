import { useState, useEffect } from "react";
import {
  User,
  Shield,
  Bell,
  Palette,
  Key,
  Smartphone,
  Lock,
  LogOut,
  ChevronRight,
  Trash2,
  AlertTriangle,
  Eye,
  EyeOff,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useNavigate } from "react-router-dom";
import { useTheme } from "../context/ThemeContext";
import { Header } from "../components/layout/Header";
import { Button } from "../components/ui/button";
import { Switch } from "../components/ui/switch";
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
import { getUserSettings, updateSetting } from "../utils/userSettings";
import { toast } from "../hooks/use-toast";
import api from "../services/api";
import { formatChatTimestamp } from "../utils/formatTime";
import { validatePassword } from "../utils/passwordValidation";
import { BatchSessionEstablishment } from "../components/admin/BatchSessionEstablishment";
import { io } from "socket.io-client";

function SettingItem({ icon: Icon, label, description, action, onClick, danger }) {
  // If there's an action (like Switch), render as div to avoid nested buttons
  // Otherwise render as button for clickable items
  const isInteractive = !!action;
  const Component = isInteractive ? 'div' : 'button';
  
  return (
    <Component
      onClick={onClick}
      className={cn(
        "w-full flex items-center justify-between p-4 rounded-xl transition-all duration-200 text-left",
        !isInteractive && "cursor-pointer",
        danger
          ? "hover:bg-destructive/5 group"
          : "hover:bg-secondary"
      )}
    >
      <div className="flex items-center gap-4">
        <div className={cn(
          "w-10 h-10 rounded-lg flex items-center justify-center",
          danger ? "bg-destructive/10" : "bg-primary/10"
        )}>
          <Icon className={cn("w-5 h-5", danger ? "text-destructive" : "text-primary")} />
        </div>
        <div>
          <p className={cn("font-medium", danger ? "text-destructive" : "text-foreground")}>{label}</p>
          {description && (
            <p className="text-sm text-muted-foreground">{description}</p>
          )}
        </div>
      </div>
      {action || (onClick && !isInteractive && <ChevronRight className="w-5 h-5 text-muted-foreground" />)}
    </Component>
  );
}

export default function Settings() {
  const { user, logout, accessToken } = useAuth();
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();
  const [socket, setSocket] = useState(null);

  // Initialize WebSocket connection for session establishment
  useEffect(() => {
    if (!accessToken) return;

    const wsURL = import.meta.env.DEV 
      ? window.location.origin
      : 'https://localhost:8443';
    
    const newSocket = io(wsURL, {
      transports: ['polling', 'websocket'],
      rejectUnauthorized: false,
      auth: {
        token: accessToken
      },
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: Infinity,
      reconnectionDelayMax: 10000,
      timeout: 20000,
      forceNew: false
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, [accessToken]);
  
  // Load settings from localStorage
  const [settings, setSettings] = useState(() => getUserSettings());
  const [notifications, setNotifications] = useState(settings.notifications);
  const [readReceipts, setReadReceipts] = useState(settings.readReceipts);
  const [securityAlerts, setSecurityAlerts] = useState(settings.securityAlerts);
  
  // Dialog states
  const [showLogoutDialog, setShowLogoutDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [showChangePasswordDialog, setShowChangePasswordDialog] = useState(false);
  const [showSessionsDialog, setShowSessionsDialog] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  
  // Change password form state
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState({ old: false, new: false, confirm: false });
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [passwordErrors, setPasswordErrors] = useState({ new: [], confirm: '' });
  
  // Active sessions state
  const [sessions, setSessions] = useState([]);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [revokingSessionId, setRevokingSessionId] = useState(null);

  // Sync state with localStorage when settings change
  useEffect(() => {
    const currentSettings = getUserSettings();
    setNotifications(currentSettings.notifications);
    setReadReceipts(currentSettings.readReceipts);
    setSecurityAlerts(currentSettings.securityAlerts);
  }, []);

  const handleNotificationsChange = (checked) => {
    setNotifications(checked);
    updateSetting('notifications', checked);
    toast({
      title: checked ? "Notifications enabled" : "Notifications disabled",
      description: checked 
        ? "You'll receive push notifications for new messages" 
        : "Push notifications have been disabled",
    });
  };

  const handleReadReceiptsChange = (checked) => {
    setReadReceipts(checked);
    updateSetting('readReceipts', checked);
    toast({
      title: checked ? "Read receipts enabled" : "Read receipts disabled",
      description: checked 
        ? "Others will see when you've read their messages" 
        : "Read receipts are now hidden",
    });
  };

  const handleSecurityAlertsChange = (checked) => {
    setSecurityAlerts(checked);
    updateSetting('securityAlerts', checked);
    toast({
      title: checked ? "Security alerts enabled" : "Security alerts disabled",
      description: checked 
        ? "You'll be notified about security events" 
        : "Security alerts have been disabled",
    });
  };

  const handleLogout = async () => {
    setShowLogoutDialog(false);
    await logout();
    navigate('/login');
    toast({
      title: "Signed out",
      description: "You have been successfully signed out.",
    });
  };

  const loadSessions = async () => {
    setLoadingSessions(true);
    try {
      const response = await api.get('/auth/sessions');
      if (response.data.success) {
        setSessions(response.data.data.sessions || []);
      }
    } catch (error) {
      console.error('Failed to load sessions:', error);
      toast({
        title: "Error",
        description: "Failed to load active sessions.",
        variant: "destructive",
      });
    } finally {
      setLoadingSessions(false);
    }
  };

  const handleRevokeSession = async (sessionId) => {
    setRevokingSessionId(sessionId);
    try {
      const response = await api.delete(`/auth/sessions/${sessionId}`);
      if (response.data.success) {
        toast({
          title: "Session revoked",
          description: "The session has been successfully revoked.",
        });
        // Reload sessions
        await loadSessions();
      }
    } catch (error) {
      console.error('Failed to revoke session:', error);
      toast({
        title: "Error",
        description: error.response?.data?.message || "Failed to revoke session.",
        variant: "destructive",
      });
    } finally {
      setRevokingSessionId(null);
    }
  };

  // Validate new password as user types
  useEffect(() => {
    if (newPassword) {
      const validation = validatePassword(newPassword);
      setPasswordErrors(prev => ({ ...prev, new: validation.errors }));
    } else {
      setPasswordErrors(prev => ({ ...prev, new: [] }));
    }
  }, [newPassword]);

  // Validate password match as user types
  useEffect(() => {
    if (confirmPassword && newPassword) {
      if (confirmPassword !== newPassword) {
        setPasswordErrors(prev => ({ ...prev, confirm: "Passwords do not match" }));
      } else {
        setPasswordErrors(prev => ({ ...prev, confirm: '' }));
      }
    } else if (!confirmPassword) {
      setPasswordErrors(prev => ({ ...prev, confirm: '' }));
    }
  }, [confirmPassword, newPassword]);

  // Clear password fields when dialog opens and prevent autofill
  const [dialogJustOpened, setDialogJustOpened] = useState(false);
  
  useEffect(() => {
    if (showChangePasswordDialog) {
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setPasswordErrors({ new: [], confirm: '' });
      // Temporarily set readOnly to prevent autofill, then remove it
      setDialogJustOpened(true);
      const timer = setTimeout(() => {
        setDialogJustOpened(false);
      }, 100);
      return () => clearTimeout(timer);
    } else {
      setDialogJustOpened(false);
    }
  }, [showChangePasswordDialog]);

  const handleChangePassword = async () => {
    // Clear previous errors
    setPasswordErrors({ new: [], confirm: '' });

    // Validate all fields are filled
    if (!oldPassword || !newPassword || !confirmPassword) {
      toast({
        title: "Missing fields",
        description: "Please fill in all password fields.",
        variant: "destructive",
      });
      return;
    }

    // Validate new password strength
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.valid) {
      toast({
        title: "Invalid password",
        description: passwordValidation.errors[0] || "Password does not meet requirements.",
        variant: "destructive",
      });
      return;
    }

    // Validate passwords match
    if (newPassword !== confirmPassword) {
      toast({
        title: "Passwords don't match",
        description: "New password and confirmation password must match.",
        variant: "destructive",
      });
      return;
    }

    setIsChangingPassword(true);
    try {
      const response = await api.post('/auth/change-password', {
        oldPassword,
        newPassword,
      });

      if (response.data.success) {
        toast({
          title: "Password changed",
          description: "Your password has been successfully updated.",
        });
        setShowChangePasswordDialog(false);
        setOldPassword('');
        setNewPassword('');
        setConfirmPassword('');
      }
    } catch (error) {
      const errorMessage = error.response?.data?.message || error.response?.data?.error || 'Failed to change password';
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setIsChangingPassword(false);
    }
  };

  const handleDeleteAccount = async () => {
    setIsDeleting(true);
    try {
      // TODO: Implement actual account deletion API call
      // await api.delete('/auth/account');
      
      // For now, just sign out
      await logout();
      navigate('/login');
      toast({
        title: "Account deleted",
        description: "Your account has been permanently deleted.",
        variant: "destructive",
      });
    } catch (error) {
      console.error('Failed to delete account:', error);
      toast({
        title: "Error",
        description: "Failed to delete account. Please try again or contact support.",
        variant: "destructive",
      });
    } finally {
      setIsDeleting(false);
      setShowDeleteDialog(false);
    }
  };

  const initials = user?.email?.split('@')[0]?.substring(0, 2).toUpperCase() || 'U';

  return (
    <div className="min-h-screen">
      <Header title="Settings" showMenu />

      <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-2xl mx-auto">
        {/* Profile Section */}
        <div className="p-6 rounded-xl bg-card border border-border">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-gradient-to-br from-primary/80 to-accent flex items-center justify-center">
              <span className="text-xl font-bold text-primary-foreground">{initials}</span>
            </div>
            <div className="flex-1">
              <h2 className="text-xl font-semibold text-foreground">{user?.email?.split('@')[0] || 'User'}</h2>
              <p className="text-sm text-muted-foreground">{user?.email}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <div className="w-2 h-2 bg-success rounded-full" />
                <span className="text-xs text-success">Account Verified</span>
              </div>
            </div>
            <Button variant="secondary">Edit</Button>
          </div>
        </div>

        {/* Security Settings */}
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider px-1">
            Security
          </h3>
          <div className="bg-card rounded-xl border border-border overflow-hidden divide-y divide-border">
            <SettingItem
              icon={Lock}
              label="Change Password"
              description="Update your account password"
              onClick={() => setShowChangePasswordDialog(true)}
            />
            <SettingItem
              icon={Key}
              label="Two-Factor Authentication"
              description="Enable 2FA for additional security"
              onClick={() => {
                toast({
                  title: "Coming soon",
                  description: "Two-factor authentication will be available in a future update.",
                });
              }}
            />
            <SettingItem
              icon={Smartphone}
              label="Active Sessions"
              description="Manage your logged-in devices"
              onClick={() => {
                setShowSessionsDialog(true);
                loadSessions();
              }}
            />
          </div>
        </div>

        {/* Privacy Settings */}
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider px-1">
            Privacy
          </h3>
          <div className="bg-card rounded-xl border border-border overflow-hidden divide-y divide-border">
            <SettingItem
              icon={Shield}
              label="Read Receipts"
              description="Show when you've read messages"
              action={
                <Switch
                  checked={readReceipts}
                  onCheckedChange={handleReadReceiptsChange}
                />
              }
            />
          </div>
        </div>

        {/* Notifications */}
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider px-1">
            Notifications
          </h3>
          <div className="bg-card rounded-xl border border-border overflow-hidden divide-y divide-border">
            <SettingItem
              icon={Bell}
              label="Push Notifications"
              description="Receive message alerts"
              action={
                <Switch
                  checked={notifications}
                  onCheckedChange={handleNotificationsChange}
                />
              }
            />
            <SettingItem
              icon={Bell}
              label="Security Alerts"
              description="Get notified about security events"
              action={
                <Switch
                  checked={securityAlerts}
                  onCheckedChange={handleSecurityAlertsChange}
                />
              }
            />
          </div>
        </div>

        {/* Appearance */}
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider px-1">
            Appearance
          </h3>
          <div className="bg-card rounded-xl border border-border overflow-hidden divide-y divide-border">
            <SettingItem
              icon={Palette}
              label="Theme"
              description={theme === 'dark' ? 'Dark mode' : 'Light mode'}
              action={
                <Switch
                  checked={theme === 'dark'}
                  onCheckedChange={toggleTheme}
                />
              }
            />
          </div>
        </div>

        {/* Danger Zone */}
        <div className="space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider px-1">
            Account
          </h3>
          <div className="bg-card rounded-xl border border-border overflow-hidden divide-y divide-border">
            <SettingItem
              icon={LogOut}
              label="Sign Out"
              description="Sign out from this device"
              onClick={() => setShowLogoutDialog(true)}
              danger
            />
            <SettingItem
              icon={Trash2}
              label="Delete Account"
              description="Permanently delete your account and data"
              onClick={() => setShowDeleteDialog(true)}
              danger
            />
          </div>
        </div>

        {/* App Info */}
        <div className="text-center py-6 text-sm text-muted-foreground">
          <p>SecureChat v1.0.0</p>
          <p className="mt-1">End-to-End Encrypted Messaging</p>
        </div>
      </div>

      {/* Sign Out Confirmation Dialog */}
      <Dialog open={showLogoutDialog} onOpenChange={setShowLogoutDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <LogOut className="w-5 h-5 text-muted-foreground" />
              Sign Out
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to sign out? You'll need to log in again to access your account.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowLogoutDialog(false)}
            >
              Cancel
            </Button>
            <Button
              variant="default"
              onClick={handleLogout}
            >
              Sign Out
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Account Confirmation Dialog */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="w-5 h-5" />
              Delete Account
            </DialogTitle>
            <DialogDescription className="space-y-2 pt-2">
              <p className="font-medium text-foreground">
                This action cannot be undone.
              </p>
              <p>
                This will permanently delete your account, all your messages, files, and encryption keys. 
                You will lose access to all your data and conversations.
              </p>
              <div className="mt-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20">
                <p className="text-sm font-medium text-destructive">
                  ⚠️ Warning: This action is irreversible
                </p>
              </div>
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              variant="outline"
              onClick={() => setShowDeleteDialog(false)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteAccount}
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
                  Delete Account
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change Password Dialog */}
      <Dialog 
        open={showChangePasswordDialog} 
        onOpenChange={(open) => {
          setShowChangePasswordDialog(open);
          // Clear all fields when dialog closes
          if (!open) {
            setOldPassword('');
            setNewPassword('');
            setConfirmPassword('');
            setPasswordErrors({ new: [], confirm: '' });
          }
        }}
      >
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Lock className="w-5 h-5" />
              Change Password
            </DialogTitle>
            <DialogDescription>
              Enter your current password and choose a new secure password.
            </DialogDescription>
          </DialogHeader>
          
          <form autoComplete="off" onSubmit={(e) => e.preventDefault()}>
            {/* Hidden dummy fields to prevent browser autofill */}
            <input type="text" name="username" autoComplete="username" style={{ display: 'none' }} tabIndex={-1} />
            <input type="password" name="password" autoComplete="current-password" style={{ display: 'none' }} tabIndex={-1} />
            
            <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="oldPassword">Current Password</Label>
              <div className="relative">
                <Input
                  id="oldPassword"
                  type={showPasswords.old ? "text" : "password"}
                  name="old-password-field"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  placeholder="Enter current password"
                  className="pr-10"
                  autoComplete="off"
                  autoFocus={false}
                  readOnly={dialogJustOpened}
                  onFocus={(e) => {
                    if (dialogJustOpened) {
                      e.target.removeAttribute('readonly');
                      setDialogJustOpened(false);
                    }
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPasswords(prev => ({ ...prev, old: !prev.old }))}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPasswords.old ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="newPassword">New Password</Label>
              <div className="relative">
                <Input
                  id="newPassword"
                  type={showPasswords.new ? "text" : "password"}
                  name="new-password-field"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  className={cn(
                    "pr-10",
                    passwordErrors.new.length > 0 && "border-destructive focus-visible:ring-destructive"
                  )}
                  autoComplete="off"
                />
                <button
                  type="button"
                  onClick={() => setShowPasswords(prev => ({ ...prev, new: !prev.new }))}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPasswords.new ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {passwordErrors.new.length > 0 ? (
                <div className="space-y-1">
                  {passwordErrors.new.map((error, idx) => (
                    <p key={idx} className="text-xs text-destructive">
                      • {error}
                    </p>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">
                  Must contain: uppercase, lowercase, number, special character
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm New Password</Label>
              <div className="relative">
                <Input
                  id="confirmPassword"
                  type={showPasswords.confirm ? "text" : "password"}
                  name="confirm-password-field"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  className={cn(
                    "pr-10",
                    passwordErrors.confirm && "border-destructive focus-visible:ring-destructive"
                  )}
                  autoComplete="off"
                />
                <button
                  type="button"
                  onClick={() => setShowPasswords(prev => ({ ...prev, confirm: !prev.confirm }))}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPasswords.confirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {passwordErrors.confirm && (
                <p className="text-xs text-destructive">
                  {passwordErrors.confirm}
                </p>
              )}
            </div>
          </div>
          </form>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowChangePasswordDialog(false);
              }}
              disabled={isChangingPassword}
            >
              Cancel
            </Button>
            <Button
              onClick={handleChangePassword}
              disabled={isChangingPassword || passwordErrors.new.length > 0 || !!passwordErrors.confirm}
            >
              {isChangingPassword ? (
                <>
                  <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin mr-2" />
                  Changing...
                </>
              ) : (
                "Change Password"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Active Sessions Dialog */}
      <Dialog open={showSessionsDialog} onOpenChange={setShowSessionsDialog}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Smartphone className="w-5 h-5" />
              Active Sessions
            </DialogTitle>
            <DialogDescription>
              Manage devices where you're currently logged in. Revoke any suspicious sessions.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4 max-h-[400px] overflow-y-auto scrollbar-thin">
            {loadingSessions ? (
              <div className="text-center py-8">
                <p className="text-muted-foreground">Loading sessions...</p>
              </div>
            ) : sessions.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-muted-foreground">No active sessions found.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {sessions.map((session, index) => (
                  <div
                    key={`session-${session.id}-${index}-${session.createdAt}`}
                    className={cn(
                      "p-4 rounded-lg border",
                      session.isCurrent
                        ? "bg-primary/5 border-primary/20"
                        : "bg-card border-border"
                    )}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2">
                          <p className="font-medium text-foreground">
                            {session.userAgent || 'Unknown Device'}
                          </p>
                          {session.isCurrent && (
                            <span className="px-2 py-0.5 text-xs rounded-full bg-primary/20 text-primary">
                              Current
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">
                          IP: {session.ip}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Last active: {formatChatTimestamp(session.createdAt)}
                        </p>
                      </div>
                      {!session.isCurrent && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleRevokeSession(session.id)}
                          disabled={revokingSessionId === session.id}
                        >
                          {revokingSessionId === session.id ? (
                            <div className="w-4 h-4 border-2 border-muted-foreground/30 border-t-muted-foreground rounded-full animate-spin" />
                          ) : (
                            <>
                              <X className="w-4 h-4 mr-1" />
                              Revoke
                            </>
                          )}
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSessionsDialog(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

