import { useEffect, useState } from "react"
import api from "../api/client"
import { useParams } from "react-router-dom"

export default function Report() {

  const { sessionId } = useParams()
  const [report, setReport] = useState("")

  useEffect(() => {
    api.get(`/sessions/${sessionId}/report`)
      .then(res => setReport(res.data.markdown))
  }, [])

  return (
    <div className="p-10">

      <h1 className="text-3xl font-bold mb-6">
        Executive Report
      </h1>

      <pre className="bg-gray-100 p-6 whitespace-pre-wrap">
        {report}
      </pre>

    </div>
  )
}
