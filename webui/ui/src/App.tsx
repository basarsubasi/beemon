import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Dashboard } from "./components/Dashboard"
import { ProcessDetails } from "./pages/ProcessDetails"
import { NamespaceDetails } from "./pages/NamespaceDetails"
import { ThemeProvider } from "./components/ThemeProvider";

function App() {
  return (
    <ThemeProvider defaultTheme="dark" storageKey="beemon-theme">
      <BrowserRouter>
        <div className="min-h-screen bg-zinc-50 dark:bg-black text-zinc-900 dark:text-zinc-100 transition-colors">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/process/:pid" element={<ProcessDetails />} />
            <Route path="/namespace/:type/:inode" element={<NamespaceDetails />} />
          </Routes>
        </div>
      </BrowserRouter>
    </ThemeProvider>
  )
}

export default App
