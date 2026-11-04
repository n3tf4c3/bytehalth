[CmdletBinding()]
param()
# Gera os ícones do ByteHalt a partir da arte original (assets/brand/bytehalt-source.png):
#   bytehalt.ico (executáveis), bytehalt-64.png (logo da barra lateral), icon-app.png (prévia)
#   tray-locked / tray-unlocked / tray-attention (.ico + .png de prévia) para a bandeja.
# A arte vem sem transparência (cantos pretos): o fundo externo vira alfa por preenchimento a partir
# dos cantos. As variantes da bandeja redesenham só o cadeado (aberto / "!") e trocam a cor de fundo.
$ErrorActionPreference = 'Stop'
$brand = (Resolve-Path (Join-Path $PSScriptRoot '..\..\assets\brand')).Path
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;

public static class ByteHaltIcons {
    // Camadas: A = alfa do quadrado arredondado; W = fração de branco (desenho) sobre o fundo.
    static int N; static float[] A; static float[] W; static Color Navy;

    public static void Load(string path) {
        using (var src = new Bitmap(path)) {
            if (src.Width != src.Height) throw new Exception("A arte precisa ser quadrada.");
            N = src.Width;
            var px = Pixels(src);
            Navy = Median(px, N / 10, N / 2, 24);
            A = new float[N * N]; W = new float[N * N];
            for (int i = 0; i < N * N; i++) {
                int r = (px[i] >> 16) & 255;
                A[i] = 1f;
                W[i] = Clamp((r - Navy.R) / (255f - Navy.R), 0.03f);
            }
            // Fundo externo: preenchimento a partir dos cantos sobre pixels mais escuros que o azul.
            var seen = new bool[N * N]; var q = new Queue<int>();
            foreach (var s in new[] { 0, N - 1, N * (N - 1), N * N - 1 }) { q.Enqueue(s); seen[s] = true; }
            float limit = Navy.B * 0.92f;
            while (q.Count > 0) {
                int i = q.Dequeue(); int x = i % N, y = i / N;
                int b = px[i] & 255, r = (px[i] >> 16) & 255;
                A[i] = Clamp(b / (float)Navy.B, 0.06f); W[i] = 0;
                if (b >= limit || r > 60) continue;
                int[] nb = { x > 0 ? i - 1 : -1, x < N - 1 ? i + 1 : -1, y > 0 ? i - N : -1, y < N - 1 ? i + N : -1 };
                foreach (int j in nb) if (j >= 0 && !seen[j]) { seen[j] = true; q.Enqueue(j); }
            }
        }
    }

    static float Clamp(float v, float snap) { if (v < snap) return 0; if (v > 1 - snap) return 1; return v; }

    static int[] Pixels(Bitmap b) {
        using (var c = new Bitmap(b.Width, b.Height, PixelFormat.Format32bppArgb)) {
            using (var g = Graphics.FromImage(c)) g.DrawImage(b, 0, 0, b.Width, b.Height);
            var d = c.LockBits(new Rectangle(0, 0, c.Width, c.Height), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            var px = new int[c.Width * c.Height]; Marshal.Copy(d.Scan0, px, 0, px.Length); c.UnlockBits(d);
            return px;
        }
    }

    static Color Median(int[] px, int cx, int cy, int r) {
        var rs = new List<int>(); var gs = new List<int>(); var bs = new List<int>();
        for (int y = cy - r; y <= cy + r; y++) for (int x = cx - r; x <= cx + r; x++) { int p = px[y * N + x]; rs.Add((p >> 16) & 255); gs.Add((p >> 8) & 255); bs.Add(p & 255); }
        rs.Sort(); gs.Sort(); bs.Sort();
        return Color.FromArgb(rs[rs.Count / 2], gs[gs.Count / 2], bs[bs.Count / 2]);
    }

    // Edita a camada W desenhando em branco (1) ou fundo (0), com antisserrilhado.
    static void Edit(Action<Graphics> draw) {
        using (var m = new Bitmap(N, N, PixelFormat.Format32bppArgb)) {
            var d = m.LockBits(new Rectangle(0, 0, N, N), ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);
            var px = new int[N * N];
            for (int i = 0; i < px.Length; i++) { int v = (int)Math.Round(W[i] * 255); px[i] = unchecked((int)0xFF000000) | (v << 16) | (v << 8) | v; }
            Marshal.Copy(px, 0, d.Scan0, px.Length); m.UnlockBits(d);
            using (var g = Graphics.FromImage(m)) { g.SmoothingMode = SmoothingMode.HighQuality; g.PixelOffsetMode = PixelOffsetMode.HighQuality; draw(g); }
            d = m.LockBits(new Rectangle(0, 0, N, N), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            Marshal.Copy(d.Scan0, px, 0, px.Length); m.UnlockBits(d);
            for (int i = 0; i < px.Length; i++) if (A[i] > 0) W[i] = ((px[i] >> 16) & 255) / 255f;
        }
    }

    // Medidas da arte original (1254 px), escaladas para N.
    static float S(float v) { return v * N / 1254f; }

    // Cadeado aberto: apaga a alça e a redesenha erguida, com a perna direita solta.
    public static void OpenShackle() {
        Edit(g => {
            using (var bg = new SolidBrush(Color.Black)) g.FillRectangle(bg, S(474), S(322), S(304), S(207));
            using (var pen = new Pen(Color.White, S(55))) {
                pen.StartCap = LineCap.Flat; pen.EndCap = LineCap.Round; pen.LineJoin = LineJoin.Round;
                float lx = S(509.5f), rx = S(742.5f), cy = S(475 - 62), r = S(116.5f);
                var path = new GraphicsPath();
                path.AddLine(lx, S(560), lx, cy);
                path.AddArc(S(626) - r, cy - r, 2 * r, 2 * r, 180, 180);
                path.AddLine(rx, cy, rx, cy + S(38));
                g.DrawPath(pen, path);
            }
        });
    }

    // Atenção: fecha as fendas do corpo e recorta um "!" na cor de fundo.
    public static void Exclamation() {
        Edit(g => {
            using (var white = new SolidBrush(Color.White)) g.FillRectangle(white, S(535), S(585), S(182), S(197));
            using (var bg = new SolidBrush(Color.Black)) {
                using (var bar = Rounded(S(598), S(578), S(56), S(142), S(28))) g.FillPath(bg, bar);
                g.FillEllipse(bg, S(596), S(742), S(60), S(60));
            }
        });
    }

    static GraphicsPath Rounded(float x, float y, float w, float h, float r) {
        var p = new GraphicsPath();
        p.AddArc(x, y, 2 * r, 2 * r, 180, 90); p.AddArc(x + w - 2 * r, y, 2 * r, 2 * r, 270, 90);
        p.AddArc(x + w - 2 * r, y + h - 2 * r, 2 * r, 2 * r, 0, 90); p.AddArc(x, y + h - 2 * r, 2 * r, 2 * r, 90, 90);
        p.CloseFigure(); return p;
    }

    public static Bitmap Compose(int rgb) {
        var bg = rgb < 0 ? Navy : Color.FromArgb(rgb);
        var b = new Bitmap(N, N, PixelFormat.Format32bppArgb);
        var px = new int[N * N];
        for (int i = 0; i < px.Length; i++) {
            float w = W[i]; int a = (int)Math.Round(A[i] * 255);
            int r = (int)Math.Round(w * 255 + (1 - w) * bg.R), gg = (int)Math.Round(w * 255 + (1 - w) * bg.G), bb = (int)Math.Round(w * 255 + (1 - w) * bg.B);
            px[i] = (a << 24) | (r << 16) | (gg << 8) | bb;
        }
        var d = b.LockBits(new Rectangle(0, 0, N, N), ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);
        Marshal.Copy(px, 0, d.Scan0, px.Length); b.UnlockBits(d);
        return b;
    }

    // Redução em etapas (no máximo metade por vez) para não perder traços finos.
    public static Bitmap Resize(Bitmap src, int size) {
        Bitmap cur = src; bool own = false;
        while (cur.Width / 2 >= size * 2) { var h = Scale(cur, cur.Width / 2); if (own) cur.Dispose(); cur = h; own = true; }
        var r = Scale(cur, size); if (own) cur.Dispose();
        return r;
    }

    static Bitmap Scale(Bitmap src, int size) {
        var b = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(b))
        using (var ia = new ImageAttributes()) {
            ia.SetWrapMode(WrapMode.TileFlipXY);
            g.CompositingMode = CompositingMode.SourceCopy; g.CompositingQuality = CompositingQuality.HighQuality;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic; g.PixelOffsetMode = PixelOffsetMode.HighQuality; g.SmoothingMode = SmoothingMode.HighQuality;
            g.DrawImage(src, new Rectangle(0, 0, size, size), 0, 0, src.Width, src.Height, GraphicsUnit.Pixel, ia);
        }
        return b;
    }

    // ICO: entradas até 128 px em DIB 32 bits (alfa direto); 256 px em PNG.
    public static void WriteIco(Bitmap master, int[] sizes, string path) {
        var images = new List<byte[]>();
        foreach (int s in sizes) using (var b = Resize(master, s)) images.Add(s >= 256 ? Png(b) : Dib(b));
        using (var f = new FileStream(path, FileMode.Create))
        using (var w = new BinaryWriter(f)) {
            w.Write((short)0); w.Write((short)1); w.Write((short)sizes.Length);
            int offset = 6 + 16 * sizes.Length;
            for (int k = 0; k < sizes.Length; k++) {
                int s = sizes[k];
                w.Write((byte)(s >= 256 ? 0 : s)); w.Write((byte)(s >= 256 ? 0 : s)); w.Write((byte)0); w.Write((byte)0);
                w.Write((short)1); w.Write((short)32); w.Write(images[k].Length); w.Write(offset);
                offset += images[k].Length;
            }
            foreach (var img in images) w.Write(img);
        }
    }

    static byte[] Png(Bitmap b) { using (var m = new MemoryStream()) { b.Save(m, ImageFormat.Png); return m.ToArray(); } }

    static byte[] Dib(Bitmap b) {
        int s = b.Width; int maskStride = ((s + 31) / 32) * 4;
        var d = b.LockBits(new Rectangle(0, 0, s, s), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
        var px = new int[s * s]; Marshal.Copy(d.Scan0, px, 0, px.Length); b.UnlockBits(d);
        using (var m = new MemoryStream())
        using (var w = new BinaryWriter(m)) {
            w.Write(40); w.Write(s); w.Write(s * 2); w.Write((short)1); w.Write((short)32); w.Write(0);
            w.Write(s * s * 4 + maskStride * s); w.Write(0); w.Write(0); w.Write(0); w.Write(0);
            for (int y = s - 1; y >= 0; y--) for (int x = 0; x < s; x++) w.Write(px[y * s + x]);
            for (int y = s - 1; y >= 0; y--) {
                var row = new byte[maskStride];
                for (int x = 0; x < s; x++) if (((px[y * s + x] >> 24) & 255) == 0) row[x / 8] |= (byte)(0x80 >> (x % 8));
                w.Write(row);
            }
            return m.ToArray();
        }
    }

    public static void SavePng(Bitmap master, int size, string path) { using (var b = Resize(master, size)) b.Save(path, ImageFormat.Png); }
}
'@

$source = Join-Path $brand 'bytehalt-source.png'
$app = @(16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
$tray = @(16, 20, 24, 32, 40, 48, 64)
$variants = [ordered]@{
    'tray-locked'    = @{ color = -1; edit = $null }                  # azul-marinho da marca, cadeado fechado
    'tray-unlocked'  = @{ color = 0x2563EB; edit = 'OpenShackle' }    # azul, cadeado aberto
    'tray-attention' = @{ color = 0xD97706; edit = 'Exclamation' }    # laranja, "!" no cadeado
}

[ByteHaltIcons]::Load($source)
$m = [ByteHaltIcons]::Compose(-1)
[ByteHaltIcons]::WriteIco($m, $app, (Join-Path $brand 'bytehalt.ico'))
[ByteHaltIcons]::SavePng($m, 256, (Join-Path $brand 'icon-app.png'))
[ByteHaltIcons]::SavePng($m, 64, (Join-Path $brand 'bytehalt-64.png'))
$m.Dispose()
foreach ($name in $variants.Keys) {
    $v = $variants[$name]
    [ByteHaltIcons]::Load($source)
    if ($v.edit) { [ByteHaltIcons]::($v.edit)() }
    $b = [ByteHaltIcons]::Compose($v.color)
    [ByteHaltIcons]::WriteIco($b, $tray, (Join-Path $brand "$name.ico"))
    [ByteHaltIcons]::SavePng($b, 256, (Join-Path $brand "$name.png"))
    $b.Dispose()
}
Get-ChildItem $brand | Select-Object Name, Length | Format-Table -AutoSize | Out-Host
