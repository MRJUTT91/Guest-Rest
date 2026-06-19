using GTC;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace rest_guest
{
    public partial class Form1 : Form
    {
        GTCMem Memlib = new GTCMem();
        private string JUTT;

        private List<long> _patchedAddresses = new List<long>();
        private byte[] _originalBytes = new byte[] { 0x55, 0x89, 0xE5, 0x53, 0x56, 0x83, 0xE4, 0xF0, 0x8D, 0x64, 0x24, 0xF0, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xC3, 0x1B, 0xE7, 0x5A, 0x04, 0x80, 0xBB, 0x8B, 0x4B };
        private byte[] _newBytes = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

        public Form1()
        {
            InitializeComponent();
        }



      

        private void label1_Click(object sender, EventArgs e)
        {

        }

        

        private async void guna2ToggleSwitch1_CheckedChanged(object sender, EventArgs e)
        {
            Int32 proc = Process.GetProcessesByName("HD-Player")[0].Id;
            Memlib.OpenProcess(proc);

            if (guna2ToggleSwitch1.Checked) // ON
            {
                status.Text = "Code ON Wait karo...";
                status.ForeColor = Color.Red;

                var enumerable = await Memlib.AoBScan(0, long.MaxValue,
                    "55 89 E5 53 56 83 E4 F0 8D 64 24 F0 E8 00 00 00 00 5B 81 C3 1B E7 5A 04 80 BB 8B 4B",
                    true, true, false, string.Empty);

                _patchedAddresses.Clear();
                _patchedAddresses.AddRange(enumerable);

                foreach (long num in _patchedAddresses)
                {
                    Memlib.WriteMemory(num.ToString("X"), "bytes",
                        "B8 01 00 00 00 C3", string.Empty, null);
                }

                status.Text = "Code ON - Patched!";
                status.ForeColor = Color.Green;
            }
            else // OFF
            {
                status.Text = "Code OFF - Restoring...";
                status.ForeColor = Color.Yellow;

                foreach (long num in _patchedAddresses)
                {
                    // Original bytes wapis likh do
                    Memlib.WriteMemory(num.ToString("X"), "bytes",
                        "55 89 E5 53 56 83 E4 F0 8D 64 24 F0 E8 00 00 00 00 5B 81 C3 1B E7 5A 04 80 BB 8B 4B",
                        string.Empty, null);
                }

                _patchedAddresses.Clear();

                status.Text = "Code OFF - Restored!";
                status.ForeColor = Color.White;
            }

            Console.Beep(400, 500);
        }
    }
}
