"""
LOOM & CO — fashion store.  Educational lab only.
Looks like a real e-commerce storefront; underneath is a race-condition flaw
in gift-card redemption (classic coupon/double-credit abuse).
"""
import time
from flask import Flask, jsonify, request, render_template_string
import threading
lock = threading.Lock()

app = Flask(__name__)

# Per-session-less single-wallet lab state.
state = {"credit": 120.00, "giftcard_used": False, "orders": []}
FLAG = "FLAG{r4c3_c0nd1t10n_1n_th3_ch3ck0ut}"

PRODUCTS = [
    {"id": 1, "name": "Classic Cotton Tee", "price": 29.00, "cat": "Tops",
     "img": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=600&q=60"},
    {"id": 2, "name": "Slim Fit Denim", "price": 79.00, "cat": "Bottoms",
     "img": "https://images.unsplash.com/photo-1542272604-787c3835535d?auto=format&fit=crop&w=600&q=60"},
    {"id": 3, "name": "Linen Overshirt", "price": 69.00, "cat": "Tops",
     "img": "https://images.unsplash.com/photo-1603252109303-2751441dd157?auto=format&fit=crop&w=600&q=60"},
    {"id": 4, "name": "Merino Knit Sweater", "price": 95.00, "cat": "Knitwear",
     "img": "https://images.unsplash.com/photo-1576566588028-4147f3842f27?auto=format&fit=crop&w=600&q=60"},
    {"id": 5, "name": "Everyday Hoodie", "price": 64.00, "cat": "Knitwear",
     "img": "https://images.unsplash.com/photo-1556821840-3a63f95609a7?auto=format&fit=crop&w=600&q=60"},
    {"id": 6, "name": "Tailored Chinos", "price": 72.00, "cat": "Bottoms",
     "img": "https://images.unsplash.com/photo-1473966968600-fa801b869a1a?auto=format&fit=crop&w=600&q=60"},
    {"id": 99, "name": "Aurelia Wool Coat — Limited Edition", "price": 999.00, "cat": "Outerwear",
     "img": "https://images.unsplash.com/photo-1539533113208-f6df8cc8b543?auto=format&fit=crop&w=600&q=60",
     "limited": True},
]
PMAP = {p["id"]: p for p in PRODUCTS}


@app.route("/api/catalog")
def catalog():
    return jsonify({"products": PRODUCTS, "credit": round(state["credit"], 2)})


@app.route("/api/credit")
def credit():
    return jsonify({"credit": round(state["credit"], 2), "giftcard_used": state["giftcard_used"]})


@app.route("/api/redeem-giftcard", methods=["POST"])
def redeem():
    code = (request.get_json(force=True, silent=True) or {}).get("code", "")
    if code != "WELCOME100":
        return jsonify({"ok": False, "error": "Invalid gift-card code."}), 400
    # VULNERABLE: check-then-act. The card is marked used only AFTER crediting,
    # so concurrent redemptions all pass the check and stack the credit.
    if not state["giftcard_used"]:
        #time.sleep(0.25)    
        state["giftcard_used"] = True                  # payment-processing window
        state["credit"] += 100.00
        #state["giftcard_used"] = True
        return jsonify({"ok": True, "credited": 100.00, "credit": round(state["credit"], 2)})
    return jsonify({"ok": False, "error": "This gift card has already been redeemed.",
                    "credit": round(state["credit"], 2)})


@app.route("/api/checkout", methods=["POST"])
def checkout():
    pid = (request.get_json(force=True, silent=True) or {}).get("product_id")
    p = PMAP.get(pid)
    if not p:
        return jsonify({"ok": False, "error": "Unknown product."}), 404
    if state["credit"] < p["price"]:
        return jsonify({"ok": False, "error": "Insufficient store credit for this item.",
                        "credit": round(state["credit"], 2)}), 402  
                        
    state["credit"] -= p["price"]
    order = {"item": p["name"], "paid": p["price"]}
    if p.get("limited"):
        order["gift_note"] = FLAG     # the limited item unlocks the flag on the receipt
    state["orders"].append(order)
    return jsonify({"ok": True, "order": order, "credit": round(state["credit"], 2)})


@app.route("/api/reset", methods=["POST"])
def reset():
    state.update({"credit": 120.00, "giftcard_used": False, "orders": []})
    return jsonify({"ok": True, "credit": 120.00})


@app.route("/")
def home():
    return render_template_string(PAGE)


PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LOOM &amp; CO — Modern Essentials</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:wght@500;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--ink:#1a1a1a;--muted:#8a8a8a;--line:#ececec;--bg:#fafafa;--accent:#1a1a1a;--sale:#b23a2f}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;color:var(--ink);background:#fff}
a{color:inherit;text-decoration:none}
.bar{background:var(--ink);color:#fff;text-align:center;font-size:12.5px;letter-spacing:.06em;padding:8px}
header{display:flex;align-items:center;justify-content:space-between;padding:18px 36px;border-bottom:1px solid var(--line);position:sticky;top:0;background:#fff;z-index:5}
.logo{font-family:Fraunces,serif;font-size:26px;font-weight:600;letter-spacing:.02em;display:flex;align-items:center;gap:10px}
.logo svg{display:block}
nav.links{display:flex;gap:26px;font-size:14px;font-weight:500}
nav.links a{color:#444}nav.links a:hover{color:#000}
.tools{display:flex;align-items:center;gap:20px;font-size:14px}
.credit{background:#f3f1ee;border-radius:999px;padding:7px 14px;font-weight:600;font-size:13px}
.cartbtn{position:relative;cursor:pointer}
.hero{padding:60px 36px;display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:center;background:linear-gradient(180deg,#fafafa,#fff)}
.hero h1{font-family:Fraunces,serif;font-size:46px;line-height:1.05;margin:0 0 14px;font-weight:600}
.hero p{color:var(--muted);font-size:16px;max-width:420px;margin:0 0 22px}
.hero .cta{display:inline-block;background:var(--ink);color:#fff;padding:13px 26px;border-radius:2px;font-weight:600;font-size:14px;letter-spacing:.04em}
.hero .himg{aspect-ratio:4/3;background:#eee url('https://images.unsplash.com/photo-1490114538077-0a7f8cb49891?auto=format&fit=crop&w=1000&q=60') center/cover;border-radius:4px}
@media(max-width:820px){.hero{grid-template-columns:1fr;padding:34px 20px}.hero h1{font-size:34px}header{padding:14px 18px}nav.links{display:none}}
.section{padding:50px 36px}@media(max-width:820px){.section{padding:34px 18px}}
.section h2{font-family:Fraunces,serif;font-size:28px;font-weight:600;margin:0 0 4px}
.section .lead{color:var(--muted);margin:0 0 28px;font-size:15px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:26px}
@media(max-width:820px){.grid{grid-template-columns:repeat(2,1fr);gap:16px}}
.prod{cursor:default}
.prod .ph{aspect-ratio:5/6;background:#f2f2f2;border-radius:4px;overflow:hidden;position:relative}
.prod .ph img{width:100%;height:100%;object-fit:cover;transition:transform .5s}
.prod:hover .ph img{transform:scale(1.04)}
.tag{position:absolute;top:10px;left:10px;background:var(--ink);color:#fff;font-size:11px;letter-spacing:.08em;padding:4px 9px;border-radius:2px}
.tag.ltd{background:var(--sale)}
.prod .meta{display:flex;justify-content:space-between;align-items:baseline;margin-top:12px}
.prod .nm{font-weight:600;font-size:14.5px}.prod .ct{color:var(--muted);font-size:12px}
.prod .pr{font-weight:600;font-size:14.5px}
.add{margin-top:10px;width:100%;background:#fff;border:1px solid var(--ink);color:var(--ink);padding:10px;border-radius:2px;font-weight:600;font-size:13px;letter-spacing:.03em;cursor:pointer}
.add:hover{background:var(--ink);color:#fff}
.giftcard{background:#f7f5f2;border-radius:6px;padding:28px;display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin-top:12px}
.giftcard input{padding:12px 14px;border:1px solid #ddd;border-radius:3px;font-size:14px;font-family:ui-monospace,monospace;min-width:200px}
.giftcard button{background:var(--ink);color:#fff;border:0;padding:12px 20px;border-radius:3px;font-weight:600;cursor:pointer}
.msg{font-size:14px;margin-left:4px}
/* cart drawer */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;z-index:20}
.drawer{position:fixed;top:0;right:-420px;width:400px;max-width:92vw;height:100%;background:#fff;z-index:21;transition:right .3s;display:flex;flex-direction:column;box-shadow:-10px 0 40px rgba(0,0,0,.12)}
.drawer.open{right:0}.overlay.open{display:block}
.drawer .dh{padding:20px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;font-family:Fraunces,serif;font-size:20px}
.drawer .body{flex:1;overflow:auto;padding:16px 20px}
.drawer .foot{border-top:1px solid var(--line);padding:18px 20px}
.citem{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}
.citem img{width:60px;height:72px;object-fit:cover;border-radius:3px}
.citem .cn{font-weight:600;font-size:14px}.citem .cp{color:var(--muted);font-size:13px}
.checkout{width:100%;background:var(--ink);color:#fff;border:0;padding:14px;border-radius:3px;font-weight:600;cursor:pointer;font-size:14px;letter-spacing:.04em}
.rowline{display:flex;justify-content:space-between;font-size:14px;margin:6px 0}
.receipt{background:#f3f8f3;border:1px solid #cfe8cf;border-radius:6px;padding:16px;margin-top:12px;font-size:14px}
.receipt .flag{font-family:ui-monospace,monospace;background:#fff;border:1px dashed #cfe8cf;border-radius:4px;padding:8px;margin-top:8px;word-break:break-all}
footer{border-top:1px solid var(--line);padding:40px 36px;color:var(--muted);font-size:13px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:16px}
.x{cursor:pointer;font-size:22px;color:#999}
</style></head><body>

<div class="bar">FREE SHIPPING ON ORDERS OVER $75 · EASY 30-DAY RETURNS</div>

<header>
  <div class="logo">
    <svg width="30" height="30" viewBox="0 0 40 40" fill="none"><rect width="40" height="40" rx="8" fill="#1a1a1a"/><path d="M11 12v16M11 28h8M23 12l3 10 3-10M29 12v16" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    LOOM &amp; CO
  </div>
  <nav class="links"><a href="#shop">New In</a><a href="#shop">Clothing</a><a href="#shop">Knitwear</a><a href="#shop">Outerwear</a><a href="#gift">Gift Cards</a></nav>
  <div class="tools">
    <span class="credit" id="credit">$0.00 credit</span>
    <span class="cartbtn" onclick="openCart()">🛒 Cart (<span id="cartcount">0</span>)</span>
  </div>
</header>

<section class="hero">
  <div>
    <h1>Modern essentials,<br>made to last.</h1>
    <p>Thoughtfully designed wardrobe staples in natural fabrics. New autumn arrivals now in store.</p>
    <a class="cta" href="#shop">Shop the collection</a>
  </div>
  <div class="himg"></div>
</section>

<section class="section" id="shop">
  <h2>New Arrivals</h2>
  <p class="lead">Autumn / Winter 2026 — curated essentials.</p>
  <div class="grid" id="grid"></div>
</section>

<section class="section" id="gift" style="padding-top:0">
  <h2>Redeem a gift card</h2>
  <p class="lead">Have a gift card? Apply it to your store credit at checkout.</p>
  <div class="giftcard">
    <input id="gcode" placeholder="Gift card code" value="WELCOME100">
    <button onclick="redeem()">Apply gift card</button>
    <span class="msg muted" id="gmsg">Welcome offer: redeem once for $100 store credit.</span>
  </div>
</section>

<footer>
  <div>© 2026 LOOM &amp; CO. All rights reserved.</div>
  <div>Shipping · Returns · Privacy · Contact</div>
</footer>

<div class="overlay" id="ov" onclick="closeCart()"></div>
<div class="drawer" id="drawer">
  <div class="dh">Your Cart <span class="x" onclick="closeCart()">×</span></div>
  <div class="body" id="cartbody"></div>
  <div class="foot">
    <div class="rowline"><span>Store credit</span><span id="d_credit">$0.00</span></div>
    <div class="rowline" style="font-weight:600"><span>Subtotal</span><span id="d_total">$0.00</span></div>
    <div id="receipt"></div>
    <button class="checkout" onclick="checkout()" style="margin-top:12px">Checkout</button>
  </div>
</div>

<script>
const money=n=>"$"+Number(n).toFixed(2);
let CART=[], CREDIT=0, PRODUCTS=[];
const $=s=>document.querySelector(s);
const fallback="https://placehold.co/600x720?text=";

async function load(){
  const r=await fetch("/api/catalog");const j=await r.json();
  PRODUCTS=j.products;CREDIT=j.credit;renderGrid();updateCredit();
}
function updateCredit(){$("#credit").textContent=money(CREDIT)+" credit";$("#d_credit").textContent=money(CREDIT);}
function renderGrid(){
  $("#grid").innerHTML=PRODUCTS.map(p=>`
    <div class="prod">
      <div class="ph">${p.limited?'<span class="tag ltd">LIMITED</span>':(p.id<=3?'<span class="tag">NEW</span>':'')}
        <img src="${p.img}" onerror="this.src='${fallback}'+encodeURIComponent('${p.name}')" alt="${p.name}"></div>
      <div class="meta"><div><div class="nm">${p.name}</div><div class="ct">${p.cat}</div></div><div class="pr">${money(p.price)}</div></div>
      <button class="add" onclick="addCart(${p.id})">Add to cart</button>
    </div>`).join('');
}
function addCart(id){const p=PRODUCTS.find(x=>x.id===id);CART.push(p);$("#cartcount").textContent=CART.length;renderCart();openCart();}
function renderCart(){
  $("#cartbody").innerHTML=CART.length?CART.map((p,i)=>`
    <div class="citem"><img src="${p.img}" onerror="this.src='${fallback}X'">
      <div style="flex:1"><div class="cn">${p.name}</div><div class="cp">${p.cat}</div></div>
      <div><div class="cp">${money(p.price)}</div><a class="cp" style="color:#b23a2f;cursor:pointer" onclick="rm(${i})">Remove</a></div></div>`).join(''):'<p class="muted" style="padding:20px 0">Your cart is empty.</p>';
  const total=CART.reduce((s,p)=>s+p.price,0);$("#d_total").textContent=money(total);
}
function rm(i){CART.splice(i,1);$("#cartcount").textContent=CART.length;renderCart();}
function openCart(){$("#drawer").classList.add("open");$("#ov").classList.add("open");}
function closeCart(){$("#drawer").classList.remove("open");$("#ov").classList.remove("open");}

async function redeem(){
  const r=await fetch("/api/redeem-giftcard",{method:"POST",headers:{'Content-Type':'application/json'},body:JSON.stringify({code:$("#gcode").value})});
  const j=await r.json();
  $("#gmsg").textContent=j.ok?("✓ Applied! +"+money(j.credited)+" store credit."):("⚠ "+j.error);
  if(typeof j.credit!=="undefined"){CREDIT=j.credit;updateCredit();}
}
async function checkout(){
  if(!CART.length){$("#receipt").innerHTML='<p class="muted">Add an item first.</p>';return;}
  const item=CART[CART.length-1];
  const r=await fetch("/api/checkout",{method:"POST",headers:{'Content-Type':'application/json'},body:JSON.stringify({product_id:item.id})});
  const j=await r.json();
  if(j.ok){
    CREDIT=j.credit;updateCredit();
    let html=`<div class="receipt"><b>Order confirmed</b> — ${j.order.item} (${money(j.order.paid)}).<br>Thank you for shopping with LOOM &amp; CO!`;
    if(j.order.gift_note){html+=`<div class="flag">🎁 A note was included with your limited edition order:<br>${j.order.gift_note}</div>`;}
    html+=`</div>`;
    $("#receipt").innerHTML=html;CART=[];$("#cartcount").textContent=0;renderCart();
  } else {
    $("#receipt").innerHTML=`<div class="receipt" style="background:#fdf1f1;border-color:#f0c9c9">⚠ ${j.error} (credit: ${money(j.credit||CREDIT)})</div>`;
  }
}
load();
</script>
</body></html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
