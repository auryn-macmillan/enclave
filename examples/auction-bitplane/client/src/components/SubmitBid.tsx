import { useState } from "react";
import { submitBid } from "../hooks/useAuction";

interface Props {
  auctionId: number;
  onBidSubmitted: () => void;
}

export default function SubmitBid({ auctionId, onBidSubmitted }: Props) {
  const [name, setName] = useState("");
  const [bid, setBid] = useState("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !bid.trim()) return;

    const bidValue = BigInt(bid);
    if (bidValue < 0n) {
      setError("Bid must be a non-negative u64");
      return;
    }

    setLoading(true);
    setError("");
    setStatus("Preparing bid for WASM encryption...");

    try {
      const bitplanes = Array.from({ length: 64 }, () => "base64-ciphertext-placeholder");
      setStatus(`Prepared u64 bid ${bidValue.toString()} via WASM placeholder...`);
      await submitBid(auctionId, name.trim(), bitplanes);
      setStatus(`Bid submitted for ${name.trim()}`);
      setName("");
      setBid("");
      onBidSubmitted();
    } catch (e: any) {
      setError(e.message);
      setStatus("");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="card">
      <h2>Submit Bid (Auction #{auctionId})</h2>
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label>Bidder Name</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Alice"
            disabled={loading}
          />
        </div>
        <div className="field">
          <label>Bid Amount (u64)</label>
          <input
            type="text"
            inputMode="numeric"
            value={bid}
            onChange={(e) => setBid(e.target.value)}
            placeholder="Encrypt via WASM module"
            disabled={loading}
          />
        </div>
        <button type="submit" disabled={loading || !name.trim() || !bid.trim()}>
          {loading ? "Submitting..." : "Encrypt via WASM & Submit Bid"}
        </button>
      </form>
      <p className="status">WASM encryption integration will provide 64 base64 bitplanes.</p>
      {status && <p className="status">{status}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
