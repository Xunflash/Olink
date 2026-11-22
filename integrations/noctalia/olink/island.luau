--!nonstrict
-- Olink island: the phone's connection as a capsule on the bar.
--
-- Status arrives as one tab-separated line (from `olink status` at load, then
-- pushed by Olink over IPC on every change):
--   connected  phone  battery  charging  casting  transfer_dir  transfer_name  transfer_pct
-- e.g. "1\tOPPO Find X9 Ultra\t82\t1\t0\tup\tholiday.mp4\t41"; battery -1 = unknown,
-- transfer_dir "" / "up" (to the phone) / "down" (from it).

-- Like the phone's own island: black pill, thin outline, blue laptop on the
-- left, status light on the right.
local GREY = "#7a7a7a"
local GREEN = "#22c55e"
local AMBER = "#f5a524"
local BLUE = "#3b9bff"
local PILL = { fill = "#000000", border = "#3a3a3a", radius = 999, paddingH = 10, gap = 8, align = "center" }

local st = { connected = false, phone = "", battery = -1, charging = false, casting = false, dir = "", name = "", pct = 0 }

local function parse(line)
  if type(line) ~= "string" then return end
  line = line:gsub("[\r\n]+$", "")
  local f = string.split(line, "\t")
  st.connected = f[1] == "1"
  st.phone = f[2] or ""
  st.battery = tonumber(f[3] or "") or -1
  st.charging = f[4] == "1"
  st.casting = f[5] == "1"
  st.dir = f[6] or ""
  st.name = f[7] or ""
  st.pct = tonumber(f[8] or "") or 0
end

-- "OPPO Find X9 Ultra" -> "FX9U", "Find X10 Pro Max" -> "FX10PM", "realme GT 7 Pro"
-- -> "GT7P": the brand goes, words become their first letter, and model
-- numbers and all-caps words (X9, GT) stay whole.
local BRANDS = { oppo = true, oneplus = true, realme = true, oplus = true }
local function shortName(name)
  local out = {}
  for word in string.gmatch(name, "%S+") do
    if not BRANDS[string.lower(word)] then
      if string.find(word, "%d") or (string.upper(word) == word and #word > 1) then
        table.insert(out, string.upper(word))
      else
        table.insert(out, string.upper(string.sub(word, 1, 1)))
      end
    end
  end
  local s = table.concat(out)
  return s ~= "" and s or "Phone"
end

local function dot(color)
  return ui.box({ width = 8, height = 8, radius = 4, fill = color })
end

local function pill(children)
  local stack = barWidget.isVertical() and ui.column or ui.row
  barWidget.render(stack(PILL, children))
end

local function render()
  if not st.connected then
    -- Collapsed: laptop, a little space, grey light.
    pill({
      ui.glyph({ name = "device-laptop", size = 16, color = GREY }),
      ui.box({ width = 18, height = 1, fill = "#00000000" }),
      dot(GREY),
    })
    barWidget.setTooltip({ { key = "Olink", value = "Phone not connected" }, { key = "Click", value = "Open Olink" } })
    return
  end

  local busy = st.casting or st.dir ~= ""
  local items = {
    ui.glyph({ name = "device-laptop", size = 16, color = BLUE }),
    ui.label({ text = shortName(st.phone), fontSize = 11, fontWeight = "bold", color = "#ffffff" }),
  }
  if st.dir ~= "" then
    table.insert(items, ui.label({ text = `{st.dir == "up" and "↑" or "↓"} {st.pct}%`, fontSize = 11, color = AMBER, fontWeight = "bold" }))
  end
  if st.casting then
    table.insert(items, ui.glyph({ name = "cast", size = 14, color = AMBER }))
  end
  table.insert(items, dot(busy and AMBER or GREEN))
  pill(items)

  local rows = { { key = "Phone", value = st.phone ~= "" and st.phone or "connected" } }
  if st.battery >= 0 then
    table.insert(rows, { key = "Battery", value = `{st.battery}%{st.charging and " · charging" or ""}` })
  end
  if st.dir ~= "" then
    table.insert(rows, { key = st.dir == "up" and "Sending" or "Receiving", value = `{st.name} · {st.pct}%` })
  end
  if st.casting then
    table.insert(rows, { key = "Screen", value = "showing on this PC" })
  end
  table.insert(rows, { key = "Click / right-click", value = "Open Olink / show phone screen" })
  barWidget.setTooltip(rows)
end

local function refresh()
  noctalia.runAsync({ "olink", "status" }, function(r)
    if r.exitCode == 0 then parse(r.stdout) else parse("0") end
    render()
  end)
end

refresh()

-- Olink pushes changes; this slow tick only catches Olink starting or quitting.
function update()
  noctalia.setUpdateInterval(60000)
  refresh()
end

function onIpc(event, payload)
  if event == "status" then
    parse(payload)
    render()
  end
end

function onClick()
  noctalia.runAsync({ "olink" })
end

function onRightClick()
  noctalia.runAsync({ "olink", "cast" })
end
