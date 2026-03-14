import { useState } from "react"
import api from "../api/client"
import { useNavigate } from "react-router-dom"

export default function IntakeForm() {
  const navigate = useNavigate()

  const [form, setForm] = useState({
    org_name: "",
    industry: "",
    org_size_bucket: "51-500",
    mfa_enabled: false,
    privileged_access_reviews: "Never",
    joiner_mover_leaver_process: false,
    sso_enabled: false,
    vpn_in_use: false,
    network_segmentation: "Basic",
    firewall_rule_review: "Ad Hoc",
    centralized_logging: false
  })

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target

    setForm({
      ...form,
      [name]: type === "checkbox" ? checked : value
    })
  }

  const submit = async () => {
    const res = await api.post("/sessions", form)
    navigate(`/dashboard/${res.data.session_id}`)
  }

  return (
    <div className="p-10 max-w-xl mx-auto">

      <h1 className="text-3xl font-bold mb-6">
        CISO GAP Assessment
      </h1>

      <input
        className="border p-2 w-full mb-4"
        placeholder="Organization Name"
        name="org_name"
        onChange={handleChange}
      />

      <input
        className="border p-2 w-full mb-4"
        placeholder="Industry"
        name="industry"
        onChange={handleChange}
      />

      <label className="flex items-center gap-2 mb-4">
        <input
          type="checkbox"
          name="mfa_enabled"
          onChange={handleChange}
        />
        MFA Enabled
      </label>

      <label className="flex items-center gap-2 mb-4">
        <input
          type="checkbox"
          name="vpn_in_use"
          onChange={handleChange}
        />
        VPN In Use
      </label>

      <button
        onClick={submit}
        className="bg-blue-600 text-white px-4 py-2 rounded"
      >
        Run Assessment
      </button>

    </div>
  )
}
