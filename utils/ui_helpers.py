"""
ui_helpers.py
-------------
Utilidades pequeñas compartidas entre pantallas de la GUI.
"""


def center_toplevel(toplevel, parent, width, height):
    """Centra una ventana Toplevel respecto a la ventana raíz de `parent`."""
    parent.update_idletasks()
    root = parent.winfo_toplevel()
    x = root.winfo_x() + (root.winfo_width() // 2) - (width // 2)
    y = root.winfo_y() + (root.winfo_height() // 2) - (height // 2)
    toplevel.geometry(f"{width}x{height}+{max(x, 0)}+{max(y, 0)}")