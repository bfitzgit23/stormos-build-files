[core]
s0_active_plugins=core;composite;opengl;mousepoll;regex;place;move;resize;decoration;animation;wobbly;cube;rotate;wallpaper;ccp;
s0_hsize=4
s0_vsize=1

[rotate]
s0_edge_flip_pointer=false
as_edge_flip_window=false
# Flip cube: Ctrl+Alt+Left/Right and Super+Left/Right
s0_initiate_button=<Control><Alt>Left
s0_initiate_key=<Control><Alt>Left
s0_rotate_left_key=<Control><Alt>Left
s0_rotate_right_key=<Control><Alt>Right
s0_rotate_left_button=Disabled
s0_rotate_right_button=Disabled
s0_flip_time=0

[cube]
s0_color=#0a192f
s0_in=true
s0_scale_image=false
# Cap transparency for the classic cube look
s0_active_opacity=85

[animation]
# Open: magic lamp-ish zoom; close: minimize animation
s0_open_effects=animation:Dodge;animation:Wave;animation:Zoom;
s0_close_effects=animation:Zoom;animation:Magic Lamp;animation:Dodge;
s0_minimize_effects=animation:Magic Lamp;

[wobbly]
# Wobbly windows defaults are fine; slight friction for the classic feel
s0_friction=3.0
s0_spring_k=8.0

[decoration]
# xfwm4/gtk window decorator shadow
s0_shadow_radius=12
s0_shadow_opacity=60

[place]
s0_workarounds=true
