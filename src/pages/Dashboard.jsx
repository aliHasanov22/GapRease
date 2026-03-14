import { useEffect, useState } from "react"
import api from "../api/client"
import { useParams } from "react-router-dom"

export default function Dashboard() {

  const { sessionId } = useParams()
  const [data, setData] = useState(null)

  useEffect(() => {
    api.get(`/sessions/${sessionId}`)
      .then(res => setData(res.data))
  }, [])

  if (!data) return <div>Loading...</div>

  return (
    <div className="p-10">

      <h1 className="text-3xl font-bold mb-6">
        Assessment Dashboard
      </h1>

      <div className="grid grid-cols-3 gap-6">

        <div className="bg-white shadow p-4">
          <h2 className="font-bold">Coverage</h2>
          <p className="text-2xl">
            {data.benchmark.coverage_percent}%
          </p>
        </div>

        <div className="bg-white shadow p-4">
          <h2 className="font-bold">Maturity</h2>
          <p className="text-xl">
            {data.benchmark.maturity}
          </p>
        </div>

        <div className="bg-white shadow p-4">
          <h2 className="font-bold">Gaps</h2>
          <p className="text-xl">
            {data.board_count}
          </p>
        </div>

      </div>

    </div>
  )
}
