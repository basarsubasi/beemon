import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Dashboard } from "./components/Dashboard"
import { ProcessDetails } from "./pages/ProcessDetails"
import { NamespaceDetails } from "./pages/NamespaceDetails"

function App() {
  return (
    <div className="min-h-screen bg-zinc-950 dark text-zinc-50">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/process/:pid" element={<ProcessDetails />} />
          <Route path="/namespace/:type/:inode" element={<NamespaceDetails />} />
        </Routes>
      </BrowserRouter>
    </div>
  )
}

export default App
