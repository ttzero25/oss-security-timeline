(() => {
  "use strict";
  const canvas = document.getElementById("security-graph");
  if (!canvas) return;
  const context = canvas.getContext("2d");
  const repoSelect = document.getElementById("graph-repo");
  const densitySelect = document.getElementById("graph-density");
  const search = document.getElementById("graph-search");
  const resetButton = document.getElementById("graph-reset");
  const count = document.getElementById("graph-count");
  const detail = document.getElementById("graph-detail");
  const palette = {
    repository: "#78c7a5", package: "#6eb6ff", advisory: "#f0c36b",
    cve: "#ff8f82", cwe: "#c49cff", commit: "#8ed0c2",
    change: "#efaa73", finding: "#ff9fc9", weakness: "#b4c4bd"
  };
  let nodes = [], edges = [], byId = new Map(), adjacency = new Map(), rawData = null;
  let selected = null, hovered = null, animation = 0, ticks = 0;
  let width = 900, height = 680, zoom = 1, panX = 0, panY = 0;
  let pointer = null;

  function hash(value) {
    let output = 2166136261;
    for (const character of value) output = Math.imul(output ^ character.charCodeAt(0), 16777619);
    return output >>> 0;
  }

  function resize() {
    const rect = canvas.getBoundingClientRect();
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = Math.max(320, rect.width);
    height = Math.max(520, rect.height);
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    draw();
  }

  function initialize(data) {
    rawData = data;
    const requested = densitySelect.value === "all" ? data.nodes.length : Number(densitySelect.value || 80);
    const priority = {repository: 0, package: 1, advisory: 2, cve: 3, cwe: 4, commit: 5, finding: 6, change: 7};
    const visible = data.nodes.slice().sort((a, b) => (priority[a.kind] ?? 9) - (priority[b.kind] ?? 9) || hash(a.id) - hash(b.id)).slice(0, requested);
    const visibleIds = new Set(visible.map(node => node.id));
    nodes = visible.map((node, index) => {
      const seed = hash(node.id);
      const angle = (seed % 6283) / 1000;
      const ring = node.kind === "repository" ? 40 : 130 + (seed % 260);
      return Object.assign({}, node, {x: Math.cos(angle) * ring, y: Math.sin(angle) * ring, vx: 0, vy: 0, index});
    });
    byId = new Map(nodes.map(node => [node.id, node]));
    edges = data.edges.filter(edge => visibleIds.has(edge.source) && visibleIds.has(edge.target)).map(edge => Object.assign({}, edge, {sourceNode: byId.get(edge.source), targetNode: byId.get(edge.target)}))
      .filter(edge => edge.sourceNode && edge.targetNode);
    adjacency = new Map(nodes.map(node => [node.id, []]));
    for (const edge of edges) {
      adjacency.get(edge.source).push({node: edge.targetNode, relation: edge.relation});
      adjacency.get(edge.target).push({node: edge.sourceNode, relation: edge.relation});
    }
    selected = hovered = null;
    ticks = 0;
    count.textContent = nodes.length + "/" + data.nodes.length + "개 노드 · " + edges.length + "개 연결";
    showDetail(null);
    fit();
    cancelAnimationFrame(animation);
    animation = requestAnimationFrame(simulate);
  }

  function simulate() {
    const active = ticks < 140;
    if (active) {
      const alpha = 1 - ticks / 150;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = b.x - a.x, dy = b.y - a.y;
          const distance2 = Math.max(dx * dx + dy * dy, 36);
          const force = (38 * alpha) / distance2;
          a.vx -= dx * force; a.vy -= dy * force;
          b.vx += dx * force; b.vy += dy * force;
        }
      }
      for (const edge of edges) {
        const a = edge.sourceNode, b = edge.targetNode;
        const dx = b.x - a.x, dy = b.y - a.y;
        const distance = Math.max(Math.hypot(dx, dy), 1);
        const target = edge.relation === "보안 공지" ? 95 : 72;
        const force = (distance - target) * 0.0025 * alpha;
        a.vx += dx / distance * force; a.vy += dy / distance * force;
        b.vx -= dx / distance * force; b.vy -= dy / distance * force;
      }
      for (const node of nodes) {
        node.vx += -node.x * 0.00035 * alpha;
        node.vy += -node.y * 0.00035 * alpha;
        node.vx *= 0.86; node.vy *= 0.86;
        if (!node.fixed) { node.x += node.vx; node.y += node.vy; }
      }
      ticks += 1;
    }
    draw();
    if (active || pointer) animation = requestAnimationFrame(simulate);
  }

  function nodeRadius(node) {
    const degree = (adjacency.get(node.id) || []).length;
    return node.kind === "repository" ? 11 : Math.min(8, 4 + Math.sqrt(degree));
  }

  function relatedSet() {
    if (!selected) return null;
    return new Set([selected.id].concat((adjacency.get(selected.id) || []).map(item => item.node.id)));
  }

  function draw() {
    const lightTheme = document.documentElement.dataset.theme === "light";
    context.clearRect(0, 0, width, height);
    context.save();
    context.translate(panX, panY);
    context.scale(zoom, zoom);
    const related = relatedSet();
    const query = search.value.trim().toLocaleLowerCase();
    const matches = query ? new Set(nodes.filter(node => (node.label + " " + node.detail).toLocaleLowerCase().includes(query)).map(node => node.id)) : null;
    context.lineWidth = 1 / zoom;
    for (const edge of edges) {
      const emphasized = !related || (related.has(edge.source) && related.has(edge.target));
      context.strokeStyle = emphasized ? (lightTheme ? "rgba(72,112,98,.25)" : "rgba(129,174,157,.22)") : (lightTheme ? "rgba(90,110,103,.06)" : "rgba(91,112,104,.04)");
      context.beginPath();
      context.moveTo(edge.sourceNode.x, edge.sourceNode.y);
      context.lineTo(edge.targetNode.x, edge.targetNode.y);
      context.stroke();
    }
    for (const node of nodes) {
      const emphasized = (!related || related.has(node.id)) && (!matches || matches.has(node.id));
      const radius = nodeRadius(node);
      context.globalAlpha = emphasized ? 1 : 0.18;
      context.fillStyle = palette[node.kind] || palette.weakness;
      context.beginPath();
      context.arc(node.x, node.y, radius, 0, Math.PI * 2);
      context.fill();
      if (node === selected || node === hovered || (matches && matches.has(node.id))) {
        context.strokeStyle = lightTheme ? "#203a31" : "#eaf8f2";
        context.lineWidth = 2 / zoom;
        context.stroke();
      }
      const showLabel = node.kind === "repository" || node === selected || node === hovered || (matches && matches.has(node.id)) || zoom > 1.8;
      if (showLabel) {
        context.globalAlpha = emphasized ? 1 : 0.3;
        context.fillStyle = lightTheme ? "#263b33" : "#dcebe5";
        context.font = Math.max(10, 12 / zoom) + "px system-ui, sans-serif";
        context.fillText(node.label.slice(0, 38), node.x + radius + 4 / zoom, node.y + 4 / zoom);
      }
    }
    context.globalAlpha = 1;
    context.restore();
  }

  function canvasPoint(event) {
    const rect = canvas.getBoundingClientRect();
    return {sx: event.clientX - rect.left, sy: event.clientY - rect.top};
  }

  function worldPoint(event) {
    const point = canvasPoint(event);
    return Object.assign({}, point, {x: (point.sx - panX) / zoom, y: (point.sy - panY) / zoom});
  }

  function nearest(event) {
    const point = worldPoint(event);
    let result = null, best = 16 / zoom;
    for (const node of nodes) {
      const distance = Math.hypot(node.x - point.x, node.y - point.y);
      if (distance < best + nodeRadius(node)) { result = node; best = distance; }
    }
    return result;
  }

  function showDetail(node) {
    detail.replaceChildren();
    const eyebrow = document.createElement("span");
    eyebrow.className = "eyebrow";
    eyebrow.textContent = node ? node.kind.toUpperCase() : "SELECT A NODE";
    const heading = document.createElement("h2");
    heading.textContent = node ? node.label : "노드를 선택하세요";
    const description = document.createElement("p");
    description.textContent = node ? (node.detail || "추가 설명 없음") : "드래그로 이동하고, 휠로 확대·축소할 수 있습니다. 노드를 선택하면 직접 연결된 관계가 강조됩니다.";
    detail.append(eyebrow, heading, description);
    if (!node) return;
    const list = document.createElement("ul");
    list.className = "graph-connections";
    for (const item of (adjacency.get(node.id) || []).slice(0, 40)) {
      const row = document.createElement("li");
      const relation = document.createElement("span");
      relation.textContent = item.relation;
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = item.node.label;
      button.addEventListener("click", () => { selected = item.node; showDetail(item.node); draw(); });
      row.append(relation, button);
      list.append(row);
    }
    detail.append(list);
  }

  function fit() {
    if (!nodes.length) { zoom = 1; panX = width / 2; panY = height / 2; draw(); return; }
    const xs = nodes.map(node => node.x), ys = nodes.map(node => node.y);
    const minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
    const minY = Math.min.apply(null, ys), maxY = Math.max.apply(null, ys);
    zoom = Math.max(0.2, Math.min(1.5, Math.min((width - 80) / Math.max(maxX - minX, 100), (height - 80) / Math.max(maxY - minY, 100))));
    panX = width / 2 - (minX + maxX) / 2 * zoom;
    panY = height / 2 - (minY + maxY) / 2 * zoom;
    draw();
  }

  canvas.addEventListener("pointerdown", event => {
    const point = worldPoint(event);
    const node = nearest(event);
    pointer = {id: event.pointerId, node, startX: point.sx, startY: point.sy, panX, panY};
    if (node) { node.fixed = true; selected = node; showDetail(node); }
    canvas.setPointerCapture(event.pointerId);
    draw();
  });
  canvas.addEventListener("pointermove", event => {
    if (pointer && pointer.id === event.pointerId) {
      const point = worldPoint(event);
      if (pointer.node) { pointer.node.x = point.x; pointer.node.y = point.y; pointer.node.vx = pointer.node.vy = 0; }
      else { panX = pointer.panX + point.sx - pointer.startX; panY = pointer.panY + point.sy - pointer.startY; }
      draw();
      return;
    }
    hovered = nearest(event);
    canvas.style.cursor = hovered ? "pointer" : "grab";
    draw();
  });
  canvas.addEventListener("pointerup", event => {
    if (pointer && pointer.node) pointer.node.fixed = false;
    pointer = null;
    canvas.releasePointerCapture(event.pointerId);
    draw();
  });
  canvas.addEventListener("pointerleave", () => { if (!pointer) { hovered = null; draw(); } });
  canvas.addEventListener("wheel", event => {
    event.preventDefault();
    const point = canvasPoint(event);
    const oldZoom = zoom;
    zoom = Math.max(0.15, Math.min(4, zoom * Math.exp(-event.deltaY * 0.001)));
    panX = point.sx - (point.sx - panX) * zoom / oldZoom;
    panY = point.sy - (point.sy - panY) * zoom / oldZoom;
    draw();
  }, {passive: false});

  async function load() {
    count.textContent = "관계 데이터 불러오는 중…";
    const query = repoSelect.value ? "?repo=" + encodeURIComponent(repoSelect.value) : "";
    try {
      const response = await fetch("/api/graph" + query, {headers: {"Accept": "application/json"}});
      if (!response.ok) throw new Error("HTTP " + response.status);
      initialize(await response.json());
    } catch (error) {
      count.textContent = "관계 데이터를 불러오지 못했습니다: " + error.message;
    }
  }

  repoSelect.addEventListener("change", load);
  densitySelect.addEventListener("change", () => { if (rawData) initialize(rawData); });
  search.addEventListener("input", draw);
  resetButton.addEventListener("click", fit);
  window.addEventListener("themechange", draw);
  new ResizeObserver(resize).observe(canvas);
  load();
})();
