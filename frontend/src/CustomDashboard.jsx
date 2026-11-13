import React, { useState } from "react";

// Dashboard customizável: arraste os cartões para reordenar, oculte/mostre, e a
// disposição fica salva no navegador. Sem libs externas (HTML5 drag-and-drop).
//
// props:
//   storageKey: chave única no localStorage
//   widgets: [{ id, title, node, wide? }]  (node = conteúdo já renderizado)
//   actions: nós extras no cabeçalho (botões de atualizar/relatório etc.)
//   title, subtitle

function loadLayout(key, allIds) {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(key) || "{}"); } catch { saved = {}; }
  const order = Array.isArray(saved.order) ? saved.order.filter((i) => allIds.includes(i)) : [];
  for (const id of allIds) if (!order.includes(id)) order.push(id); // novos widgets no fim
  const hidden = Array.isArray(saved.hidden) ? saved.hidden.filter((i) => allIds.includes(i)) : [];
  return { order, hidden };
}
function saveLayout(key, layout) {
  try { localStorage.setItem(key, JSON.stringify(layout)); } catch { /* ignore */ }
}

export default function CustomDashboard({ storageKey, widgets, actions, title, subtitle }) {
  const allIds = widgets.map((w) => w.id);
  const byId = Object.fromEntries(widgets.map((w) => [w.id, w]));
  const [layout, setLayout] = useState(() => loadLayout(storageKey, allIds));
  const [edit, setEdit] = useState(false);
  const [drag, setDrag] = useState(null);

  const update = (next) => { setLayout(next); saveLayout(storageKey, next); };
  const hiddenSet = new Set(layout.hidden);
  const visible = layout.order.filter((id) => !hiddenSet.has(id));
  const hiddenList = layout.order.filter((id) => hiddenSet.has(id));

  function move(fromId, toId) {
    if (fromId === toId) return;
    const order = [...layout.order];
    const fi = order.indexOf(fromId);
    order.splice(fi, 1);
    const ti = order.indexOf(toId);
    order.splice(ti, 0, fromId);
    update({ ...layout, order });
  }
  const hide = (id) => update({ ...layout, hidden: [...layout.hidden, id] });
  const show = (id) => update({ ...layout, hidden: layout.hidden.filter((x) => x !== id) });
  const reset = () => { update({ order: allIds, hidden: [] }); };

  return (
    <div>
      <div className="head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p className="muted">{subtitle}</p>}
        </div>
        <div className="row">
          {actions}
          <button className={`btn ${edit ? "primary" : ""}`} onClick={() => setEdit(!edit)}>
            {edit ? "✓ Concluir" : "✎ Personalizar"}
          </button>
        </div>
      </div>

      {edit && (
        <div className="info" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span>Arraste os cartões para reordenar. Oculte no ✕. </span>
          {hiddenList.length > 0 && <span>Mostrar:</span>}
          {hiddenList.map((id) => (
            <button key={id} className="btn" style={{ padding: "2px 8px" }} onClick={() => show(id)}>
              + {byId[id].title}
            </button>
          ))}
          <button className="btn" style={{ padding: "2px 8px", marginLeft: "auto" }} onClick={reset}>Restaurar padrão</button>
        </div>
      )}

      <div className="wgrid">
        {visible.map((id) => {
          const w = byId[id];
          return (
            <div key={id}
              className={`widget ${w.wide ? "wide" : ""} ${edit ? "editing" : ""} ${drag === id ? "dragging" : ""}`}
              draggable={edit}
              onDragStart={() => setDrag(id)}
              onDragEnd={() => setDrag(null)}
              onDragOver={(e) => { if (edit) e.preventDefault(); }}
              onDrop={(e) => { if (edit && drag) { e.preventDefault(); move(drag, id); setDrag(null); } }}>
              <div className="widgethead">
                <h3 style={{ margin: 0 }}>{edit && <span className="draghandle">⠿ </span>}{w.title}</h3>
                {edit && <button className="whide" title="Ocultar" onClick={() => hide(id)}>✕</button>}
              </div>
              {w.node}
            </div>
          );
        })}
      </div>
    </div>
  );
}
