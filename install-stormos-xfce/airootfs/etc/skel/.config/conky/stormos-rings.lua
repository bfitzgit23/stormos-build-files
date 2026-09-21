-- StormOS rings for conky (decorative accent, matches branding)
require 'cairo'

function conky_main_rings()
    if conky_window == nil then return end
    local cs = cairo_xlib_surface_create(conky_window.display,
        conky_window.drawable, conky_window.visual,
        conky_window.width, conky_window.height)
    local cr = cairo_create(cs)

    local cx = conky_window.width - 40
    local cy = 14
    local settings = {
        { name='cpu',  arg='cpu0', max=100, bg=0x0A1628, bg_alpha=0.4, fg=0x19A9FF, fg_alpha=0.8, radius=26, thickness=4, start_angle=-90 },
        { name='mem',  arg='memperc', max=100, bg=0x0A1628, bg_alpha=0.4, fg=0x2CB5FF, fg_alpha=0.8, radius=18, thickness=3, start_angle=-90 },
    }

    for i in pairs(settings) do
        local s = settings[i]
        local value = tonumber(conky_parse(string.format('${%s %s}', s.name, s.arg))) or 0
        local pct = value / s.max

        -- background ring
        cairo_arc(cr, cx, cy, s.radius, 0, 2 * math.pi)
        cairo_set_source_rgba(cr, ((s.bg >> 16) & 0xFF)/255, ((s.bg >> 8) & 0xFF)/255, (s.bg & 0xFF)/255, s.bg_alpha)
        cairo_set_line_width(cr, s.thickness)
        cairo_stroke(cr)

        -- value arc
        local end_angle = s.start_angle + (pct * 2 * math.pi)
        cairo_arc(cr, cx, cy, s.radius, s.start_angle * math.pi / 180, end_angle * math.pi / 180)
        cairo_set_source_rgba(cr, ((s.fg >> 16) & 0xFF)/255, ((s.fg >> 8) & 0xFF)/255, (s.fg & 0xFF)/255, s.fg_alpha)
        cairo_set_line_width(cr, s.thickness)
        cairo_stroke(cr)
    end

    cairo_destroy(cr)
    cairo_surface_destroy(cs)
end
