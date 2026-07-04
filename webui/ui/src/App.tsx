import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Dashboard } from "./components/Dashboard"
import { ProcessDetails } from "./pages/ProcessDetails"

function App() {
  return (
    <div className="min-h-screen bg-zinc-950 dark text-zinc-50">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/process/:pid" element={<ProcessDetails />} />
        </Routes>
      </BrowserRouter>
    </div>
  )
}

export default App
