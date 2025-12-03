import { useState } from "react";
import { Search, Filter } from "lucide-react";
import { Header } from "../components/layout/Header";
import { Input } from "../components/ui/input";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { useLogs } from "../hooks/useLogs";

const logLevels = {
  info: "bg-primary/10 text-primary",
  warning: "bg-warning/10 text-warning",
  error: "bg-destructive/10 text-destructive",
  success: "bg-success/10 text-success",
};

export default function Logs() {
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState("all");
  const { logs, loading, error } = useLogs();

  const filteredLogs = logs.filter((log) => {
    const matchesSearch = (log.message || log.title || '').toLowerCase().includes(search.toLowerCase());
    const matchesLevel = levelFilter === "all" || log.level === levelFilter;
    return matchesSearch && matchesLevel;
  });

  return (
    <div className="min-h-screen">
      <Header title="System Logs" showMenu />

      <div className="p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Search & Filters */}
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search logs..."
              className="pl-10"
            />
          </div>
          <Button variant="secondary" size="icon">
            <Filter className="w-4 h-4" />
          </Button>
        </div>

        {/* Level Filters */}
        <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin">
          {["all", "info", "warning", "error", "success"].map((level) => (
            <Button
              key={level}
              variant={levelFilter === level ? "default" : "secondary"}
              size="sm"
              onClick={() => setLevelFilter(level)}
              className="flex-shrink-0 capitalize"
            >
              {level}
            </Button>
          ))}
        </div>
        
        {/* Debug Info (remove in production) */}
        {process.env.NODE_ENV === 'development' && (
          <div className="text-xs text-muted-foreground space-y-1">
            <div>Total logs: {logs.length} | Filtered: {filteredLogs.length} | Loading: {loading ? 'Yes' : 'No'} | Error: {error || 'None'}</div>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={refetch}
              className="mt-2"
            >
              Refresh Logs
            </Button>
          </div>
        )}

        {/* Logs List */}
        {loading ? (
          <div className="text-center py-12">
            <p className="text-muted-foreground">Loading logs...</p>
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <p className="text-destructive">Error loading logs: {error}</p>
          </div>
        ) : (
          <>
            <div className="space-y-3">
              {filteredLogs.map((log, i) => (
                <Card key={log.id} className="animate-fade-in" style={{ animationDelay: `${i * 50}ms` }}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base">{log.title || log.message}</CardTitle>
                      <Badge className={logLevels[log.level] || logLevels.info}>
                        {log.level}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">{log.message}</p>
                    <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                      <span>{new Date(log.timestamp).toLocaleString()}</span>
                      {log.source && <span>• {log.source}</span>}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            {filteredLogs.length === 0 && (
              <div className="text-center py-12">
                <p className="text-muted-foreground">No logs found</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

