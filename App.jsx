import { BrowserRouter, Routes, Route } from "react-router-dom"

import IntakeForm from "./pages/IntakeForm"
import Dashboard from "./pages/Dashboard"
import GapBoard from "./pages/GapBoard"
import Report from "./pages/Report"

export default function App() {

  return (
    <BrowserRouter>

      <Routes>

        <Route path="/" element={<IntakeForm />} />

        <Route
          path="/dashboard/:sessionId"
          element={<Dashboard />}
        />

        <Route
          path="/board/:sessionId"
          element={<GapBoard />}
        />

        <Route
          path="/report/:sessionId"
          element={<Report />}
        />

      </Routes>

    </BrowserRouter>
  )
}
