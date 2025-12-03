/**
 * Batch Session Establishment Component
 * 
 * Allows a user to establish sessions with all other users in the system.
 * This component will:
 * 1. Fetch all users from the server
 * 2. For each user, generate a session ID
 * 3. Establish sessions using the KEP protocol
 * 
 * Usage: Add this component to an admin page or settings page
 */

import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { initiateSession } from '../../crypto/sessionEstablishment';
import { generateSecureSessionId } from '../../crypto/sessionIdSecurity';
import { loadSession } from '../../crypto/sessionManager';
import api from '../../services/api';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card';
import { Progress } from '../ui/progress';
import { CheckCircle, XCircle, Loader2, Users } from 'lucide-react';
import { toast } from '../../hooks/use-toast';

export function BatchSessionEstablishment({ socket }) {
  const { user, getCachedPassword } = useAuth();
  const [allUsers, setAllUsers] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isEstablishing, setIsEstablishing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);

  // Fetch all users
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        setIsLoading(true);
        // Try to get all users by searching with a common character
        // This is a workaround - ideally there would be an admin endpoint
        // Try multiple search queries to get all users
        const searchQueries = ['a', 'e', 'i', 'o', 'u', '@'];
        const allUsersSet = new Map();
        
        for (const query of searchQueries) {
          try {
            const response = await api.get('/auth/users/search', {
              params: { q: query, limit: 1000 }
            });

            if (response.data && response.data.success) {
              const users = response.data.data || [];
              users.forEach(u => {
                if (u.id !== user?.id && !allUsersSet.has(u.id)) {
                  allUsersSet.set(u.id, u);
                }
              });
            }
          } catch (err) {
            // Continue with next query
            console.warn(`Search with "${query}" failed:`, err);
          }
        }
        
        setAllUsers(Array.from(allUsersSet.values()));
      } catch (error) {
        console.error('Failed to fetch users:', error);
        toast({
          title: "Error",
          description: "Failed to fetch users. Please try again.",
          variant: "destructive",
        });
      } finally {
        setIsLoading(false);
      }
    };

    if (user) {
      fetchUsers();
    }
  }, [user]);

  /**
   * Establishes sessions with all users
   */
  const establishAllSessions = async () => {
    if (!user || !socket || allUsers.length === 0) {
      toast({
        title: "Error",
        description: "Missing required information. Please ensure you're logged in and socket is connected.",
        variant: "destructive",
      });
      return;
    }

    const password = getCachedPassword(user.id);
    if (!password) {
      toast({
        title: "Password Required",
        description: "Please log out and log back in to cache your password for session establishment.",
        variant: "destructive",
      });
      return;
    }

    setIsEstablishing(true);
    setProgress(0);
    setResults([]);

    const newResults = [];
    const total = allUsers.length;

    for (let i = 0; i < allUsers.length; i++) {
      const peer = allUsers[i];
      setCurrentUser(peer);

      try {
        // Generate session ID
        const sessionId = await generateSecureSessionId(user.id, peer.id);

        // Check if session already exists
        try {
          const existingSession = await loadSession(sessionId, user.id, password);
          if (existingSession) {
            newResults.push({
              peer: peer.email,
              status: 'exists',
              sessionId,
              message: 'Session already exists'
            });
            setProgress(((i + 1) / total) * 100);
            continue;
          }
        } catch (e) {
          // Session doesn't exist, continue to establish
        }

        // Establish session
        try {
          await initiateSession(user.id, peer.id, password, socket);
          
          newResults.push({
            peer: peer.email,
            status: 'success',
            sessionId,
            message: 'Session established successfully'
          });
        } catch (error) {
          newResults.push({
            peer: peer.email,
            status: 'error',
            sessionId,
            message: error.message || 'Failed to establish session'
          });
        }
      } catch (error) {
        newResults.push({
          peer: peer.email,
          status: 'error',
          sessionId: 'unknown',
          message: error.message || 'Failed to generate session'
        });
      }

      setProgress(((i + 1) / total) * 100);
      setResults([...newResults]);

      // Small delay to avoid overwhelming the server
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    setCurrentUser(null);
    setIsEstablishing(false);

    const successCount = newResults.filter(r => r.status === 'success').length;
    const existsCount = newResults.filter(r => r.status === 'exists').length;
    const errorCount = newResults.filter(r => r.status === 'error').length;

    toast({
      title: "Session Establishment Complete",
      description: `Success: ${successCount}, Already Exists: ${existsCount}, Errors: ${errorCount}`,
      variant: successCount > 0 ? "default" : "destructive",
    });
  };

  if (!user) {
    return (
      <Card>
        <CardContent className="pt-6">
          <p className="text-muted-foreground">Please log in to establish sessions.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Users className="w-5 h-5" />
          Batch Session Establishment
        </CardTitle>
        <CardDescription>
          Establish encrypted sessions with all users in the system. This will create
          sessions that allow you to send encrypted messages to any user.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-muted-foreground">
              Found {allUsers.length} users to establish sessions with
            </p>
          </div>
          <Button
            onClick={establishAllSessions}
            disabled={isEstablishing || isLoading || allUsers.length === 0 || !socket}
          >
            {isEstablishing ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Establishing...
              </>
            ) : (
              'Establish All Sessions'
            )}
          </Button>
        </div>

        {isEstablishing && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">
                {currentUser ? `Establishing session with ${currentUser.email}...` : 'Processing...'}
              </span>
              <span className="text-muted-foreground">{Math.round(progress)}%</span>
            </div>
            <Progress value={progress} />
          </div>
        )}

        {results.length > 0 && (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            <h4 className="text-sm font-medium">Results:</h4>
            {results.map((result, index) => (
              <div
                key={index}
                className="flex items-center gap-2 p-2 rounded-lg bg-secondary text-sm"
              >
                {result.status === 'success' && (
                  <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                )}
                {result.status === 'exists' && (
                  <CheckCircle className="w-4 h-4 text-primary flex-shrink-0" />
                )}
                {result.status === 'error' && (
                  <XCircle className="w-4 h-4 text-destructive flex-shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <p className="font-medium truncate">{result.peer}</p>
                  <p className="text-xs text-muted-foreground">{result.message}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        {!socket && (
          <div className="p-3 rounded-lg bg-warning/10 border border-warning/20">
            <p className="text-sm text-warning">
              WebSocket not connected. Please ensure you're connected to the server.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

