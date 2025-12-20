import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:5000";
const COLORS = ["#0ea5e9", "#f59e0b", "#10b981", "#ef4444", "#8b5cf6", "#64748b"];

export default function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [expenses, setExpenses] = useState([]);
  const [summary, setSummary] = useState([]);
  const [form, setForm] = useState({ email: "", password: "" });
  const [expenseForm, setExpenseForm] = useState({ category: "groceries", description: "", amount: "" });
  const [insight, setInsight] = useState("");
  const [insightLoading, setInsightLoading] = useState(false);
  const [status, setStatus] = useState("");

  useEffect(() => {
    if (token) {
      fetchExpenses();
      fetchSummary();
    }
  }, [token]);

  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {};

  async function handleAuth(endpoint) {
    setStatus("Working...");
    try {
      const res = await fetch(`${API_BASE}/api/auth/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const message =
          endpoint === "register" && res.status === 409
            ? "Email already exists. Try logging in instead."
            : data.error || "Auth failed";
        setStatus(message);
        return;
      }
      setToken(data.access_token);
      localStorage.setItem("token", data.access_token);
      setUser(data.user);
      setStatus("Welcome!");
    } catch (err) {
      setStatus("Cannot reach API. Is the backend running on 5000?");
    }
  }

  async function fetchExpenses() {
    const res = await fetch(`${API_BASE}/api/expenses`, { headers: { ...authHeaders } });
    if (!res.ok) return;
    const data = await res.json();
    setExpenses(data.expenses || []);
  }

  async function fetchSummary() {
    const res = await fetch(`${API_BASE}/api/expenses/summary`, { headers: { ...authHeaders } });
    if (!res.ok) return;
    const data = await res.json();
    setSummary(data.summary || []);
  }

  async function handleCreateExpense(e) {
    e.preventDefault();
    setStatus("Saving expense...");
    const res = await fetch(`${API_BASE}/api/expenses`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify({ ...expenseForm, amount: Number(expenseForm.amount) }),
    });
    const data = await res.json();
    if (!res.ok) {
      setStatus(data.error || "Could not save expense");
      return;
    }
    setStatus("Expense saved");
    setExpenseForm({ category: "groceries", description: "", amount: "" });
    fetchExpenses();
    fetchSummary();
  }

  async function handleDeleteExpense(id) {
    setStatus("Deleting expense...");
    try {
      const res = await fetch(`${API_BASE}/api/expenses/${id}`, {
        method: "DELETE",
        headers: { ...authHeaders },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setStatus(data.error || "Could not delete expense");
        return;
      }
      setExpenses((prev) => prev.filter((exp) => exp.id !== id));
      fetchSummary();
      setStatus("Expense deleted");
    } catch (err) {
      setStatus("Cannot reach API. Is the backend running on 5000?");
    }
  }

  async function fetchInsights() {
    setStatus("Fetching AI insights...");
    setInsight("");
    setInsightLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/expenses/insights`, {
        headers: { ...authHeaders },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setStatus(data.error || "Could not fetch insights");
        return;
      }
      setInsight(data.insight || "No insight returned.");
      setStatus("AI insight ready");
    } catch (err) {
      setStatus("Cannot reach API. Is the backend running on 5000?");
    } finally {
      setInsightLoading(false);
    }
  }

  function logout() {
    setToken("");
    setUser(null);
    localStorage.removeItem("token");
    setExpenses([]);
    setSummary([]);
    setInsight("");
  }

  const total = summary.reduce((sum, item) => sum + item.total, 0);

  return (
    <div className="page">
      <header className="hero">
        <div>
          <p className="eyebrow">Personal Finance</p>
          <h1>Expense dashboard</h1>
          <p className="subhead">Track spending, get AI tips, and view category trends.</p>
        </div>
        <div className="status">{status}</div>
      </header>

      {!token ? (
        <section className="card auth-card">
          <h2>Get started</h2>
          <div className="form-grid">
            <label>Email</label>
            <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="you@example.com" />
            <label>Password</label>
            <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="••••••" />
          </div>
          <div className="actions">
            <button onClick={() => handleAuth("register")}>Register</button>
            <button className="secondary" onClick={() => handleAuth("login")}>
              Log in
            </button>
          </div>
        </section>
      ) : (
        <>
          <section className="grid">
            <div className="card">
              <div className="card-header">
                <h2>New expense</h2>
                <button className="ghost" onClick={logout}>
                  Logout
                </button>
              </div>
              <form onSubmit={handleCreateExpense} className="form-grid">
                <label>Category</label>
                <select value={expenseForm.category} onChange={(e) => setExpenseForm({ ...expenseForm, category: e.target.value })}>
                  <option value="groceries">Groceries</option>
                  <option value="transportation">Transportation</option>
                  <option value="entertainment">Entertainment</option>
                  <option value="rent">Rent</option>
                  <option value="other">Other</option>
                </select>
                <label>Description</label>
                <input value={expenseForm.description} onChange={(e) => setExpenseForm({ ...expenseForm, description: e.target.value })} placeholder="Coffee with friends" />
                <label>Amount</label>
                <input type="number" step="0.01" value={expenseForm.amount} onChange={(e) => setExpenseForm({ ...expenseForm, amount: e.target.value })} placeholder="12.50" />
                <button type="submit">Add expense</button>
              </form>
            </div>

            <div className="card">
              <div className="card-header">
                <h2>Category summary</h2>
                <span className="total">Total: ${total.toFixed(2)}</span>
              </div>
              {summary.length === 0 ? (
                <p className="muted">No expenses yet.</p>
              ) : (
                <div className="chart">
                  <ResponsiveContainer width="100%" height={240}>
                    <PieChart>
                      <Pie data={summary} dataKey="total" nameKey="category" innerRadius={60} outerRadius={90}>
                        {summary.map((_, idx) => (
                          <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="legend">
                    {summary.map((item, idx) => (
                      <div className="legend-row" key={item.category}>
                        <span className="swatch" style={{ background: COLORS[idx % COLORS.length] }} />
                        <div>
                          <p>{item.category}</p>
                          <p className="muted">${item.total.toFixed(2)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </section>

          <section className="card ai-card">
            <div className="card-header">
              <h2>AI spending coach</h2>
              <button className="secondary" onClick={fetchInsights} disabled={insightLoading || summary.length === 0}>
                {insightLoading ? "Thinking..." : "Get AI insight"}
              </button>
            </div>
            {summary.length === 0 ? (
              <p className="muted">Add a few expenses first, then ask the AI for a quick take on your habits.</p>
            ) : (
              <>
                <p className="muted">Pull a short readout of your category trends.</p>
                {insight ? <p className="insight-text">{insight}</p> : <p className="muted">Tap “Get AI insight” to fetch the latest.</p>}
              </>
            )}
          </section>

          <section className="card">
            <div className="card-header">
              <h2>Recent expenses</h2>
              <small className="muted">Most recent 100 records</small>
            </div>
            <div className="table">
              <div className="row head">
                <span>Category</span>
                <span>Description</span>
                <span>Amount</span>
                <span>Date</span>
                <span>Actions</span>
              </div>
              {expenses.map((exp) => (
                <div className="row" key={exp.id}>
                  <span className="pill">{exp.category}</span>
                  <span>{exp.description || "—"}</span>
                  <span className="amount">${exp.amount.toFixed(2)}</span>
                  <span>{new Date(exp.created_at).toLocaleString()}</span>
                  <button className="ghost danger" onClick={() => handleDeleteExpense(exp.id)}>
                    Delete
                  </button>
                </div>
              ))}
              {expenses.length === 0 && <p className="muted">Nothing to show yet.</p>}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
