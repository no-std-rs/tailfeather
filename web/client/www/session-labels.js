// Prefer the shortest peer name that distinguishes the destination.
function peerName(peer) {
  return (peer.name || "").trim().replace(/\.+$/, "");
}

export function hostLabel(ip, peers = []) {
  const peer = peers.find((candidate) => candidate.ip === ip);
  if (!peer || !peerName(peer)) return ip || "?";
  const name = peerName(peer);
  const short = name.split(".")[0];
  const others = peers.filter((candidate) => candidate.ip && candidate.ip !== ip);
  if (!others.some((candidate) => peerName(candidate).split(".")[0].toLowerCase() === short.toLowerCase())) return short;
  if (!others.some((candidate) => peerName(candidate).toLowerCase() === name.toLowerCase())) return name;
  return `${name} (${ip})`;
}

export function connectionLabel({ ip, port = 22, user, url }, peers = []) {
  let where = hostLabel(ip, peers);
  if (url) {
    try {
      where = new URL(url).host;
    } catch {
      where = url;
    }
  }
  const suffix = !url && port !== 22 ? `:${port}` : "";
  return `${user || "?"}@${where}${suffix}`;
}
