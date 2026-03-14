import { useEffect, useState } from "react"
import api from "../api/client"
import { useParams } from "react-router-dom"

export default function GapBoard() {

  const { sessionId } = useParams()
  const [items, setItems] = useState([])

  useEffect(() => {
    api.get(`/sessions/${sessionId}/board`)
      .then(res => setItems(res.data.items))
  }, [])

  return (
    <div className="p-10">

      <h1 className="text-2xl font-bold mb-6">
        GAP Board
      </h1>

      <div className="grid grid-cols-3 gap-6">

        {items.map(gap => (
          <div
            key={gap.gap_id}
            className="border p-4 shadow"
          >
            <h2 className="font-bold">
              {gap.title}
            </h2>

            <p className="text-sm text-gray-600">
              {gap.domain}
            </p>

            <p className="mt-2">
              Severity: {gap.severity}
            </p>

            <p>Status: {gap.status}</p>

          </div>
        ))}

      </div>

    </div>
  )
}
