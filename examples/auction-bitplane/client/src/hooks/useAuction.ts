const API = "/api";

export interface AuctionInfo {
  id: number;
  state: string;
  num_bids: number;
  public_key: string;
  result: {
    winner_address: string;
    winner_slot: number;
    second_address: string | null;
    second_slot: number | null;
  } | null;
}

export interface AuctionResult {
  winner_address: string;
  winner_slot: number;
  second_address: string | null;
  second_slot: number | null;
}

export async function createAuction(): Promise<{
  id: number;
  public_key: string;
}> {
  const res = await fetch(`${API}/auction/create`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getAuction(id: number): Promise<AuctionInfo> {
  const res = await fetch(`${API}/auction/${id}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function submitBid(
  auctionId: number,
  address: string,
  bitplanes: string[],
): Promise<void> {
  const res = await fetch(`${API}/auction/${auctionId}/bid`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address, bitplanes }),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function closeAuction(
  id: number,
): Promise<AuctionResult> {
  const res = await fetch(`${API}/auction/${id}/close`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getResult(
  id: number,
): Promise<AuctionResult> {
  const res = await fetch(`${API}/auction/${id}/result`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
