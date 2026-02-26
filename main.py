import sys
import tkinter as tk

from admin.admin_dashboard import AdminDashboard
from client.client_ui import ClientUI


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--admin":
        root = tk.Tk()
        _ = AdminDashboard(root)
        root.mainloop()
    else:
        root = tk.Tk()
        _ = ClientUI(root)
        root.mainloop()


if __name__ == "__main__":
    main()