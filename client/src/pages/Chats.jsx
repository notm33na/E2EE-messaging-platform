import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, Search } from "lucide-react";
import { Header } from "../components/layout/Header";
import { ChatListItem } from "../components/chat/ChatListItem";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Skeleton } from "../components/ui/skeleton";
import { NewChatDialog } from "../components/chat/NewChatDialog";
import { useChatSessions } from "../hooks/useChatSessions";

export default function Chats() {
  const [search, setSearch] = useState("");
  const [newChatOpen, setNewChatOpen] = useState(false);
  const [filter, setFilter] = useState("All");
  const navigate = useNavigate();
  const { sessions, loading, error } = useChatSessions();

  // Filter chats based on search and category
  const filteredChats = sessions.filter((chat) => {
    // Search filter
    const matchesSearch = chat.name.toLowerCase().includes(search.toLowerCase()) ||
                         (chat.lastMessage && chat.lastMessage.toLowerCase().includes(search.toLowerCase()));
    
    if (!matchesSearch) return false;

    // Category filter
    switch (filter) {
      case "Unread":
        return chat.unreadCount > 0;
      case "Groups":
        // Groups not implemented yet, return false for now
        return false;
      case "Archived":
        // Archived not implemented yet, return false for now
        return false;
      case "All":
      default:
        return true;
    }
  });

  return (
    <div className="min-h-screen flex flex-col">
      <Header title="Chats" showMenu showSearch={false} />

      <div className="flex-1 p-4 sm:p-6">
        {/* Search & New Chat */}
        <div className="flex items-center gap-3 mb-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search conversations..."
              className="pl-10"
            />
          </div>
          <Button 
            size="icon" 
            className="flex-shrink-0"
            onClick={() => setNewChatOpen(true)}
          >
            <Plus className="w-5 h-5" />
          </Button>
        </div>

        {/* Chat Categories */}
        <div className="flex gap-2 mb-4 overflow-x-auto pb-2 scrollbar-thin">
          {["All", "Unread", "Groups", "Archived"].map((cat) => (
            <Button
              key={cat}
              variant={filter === cat ? "default" : "secondary"}
              size="sm"
              className="flex-shrink-0"
              onClick={() => setFilter(cat)}
            >
              {cat}
            </Button>
          ))}
        </div>

        {/* Chat List */}
        {loading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 p-3 rounded-xl bg-card border border-border">
                <Skeleton className="w-12 h-12 rounded-full" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-3 w-48" />
                </div>
              </div>
            ))}
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <p className="text-destructive">Error loading conversations: {error}</p>
          </div>
        ) : (
          <>
            <div className="space-y-2">
              {filteredChats.map((chat, i) => (
                <div
                  key={chat.id}
                  className="animate-fade-in"
                  style={{ animationDelay: `${i * 50}ms` }}
                >
                  <ChatListItem
                    {...chat}
                    onClick={() => navigate(`/chat/${chat.sessionId}`, { 
                      state: { peerId: chat.peerId } 
                    })}
                  />
                </div>
              ))}
            </div>

            {filteredChats.length === 0 && (
              <div className="text-center py-12">
                <p className="text-muted-foreground">No conversations found</p>
                <Button className="mt-4" onClick={() => navigate('/dashboard')}>
                  Go to Dashboard
                </Button>
              </div>
            )}
          </>
        )}
      </div>

      {/* New Chat Dialog */}
      <NewChatDialog open={newChatOpen} onOpenChange={setNewChatOpen} />
    </div>
  );
}

