# ssd1306.py — MicroPython SSD1306 OLED driver (I2C)
# Works with 128x64 or 128x32 displays.
# Usage:
#   from machine import I2C, Pin
#   from ssd1306 import SSD1306_I2C
#   i2c = I2C(0, sda=Pin(0), scl=Pin(1), freq=400000)  # or your pins
#   oled = SSD1306_I2C(128, 64, i2c, addr=0x3C)       # 128x64 example
#   oled.text("Hello", 0, 0); oled.show()

from micropython import const
import framebuf
import time

# Commands
SET_CONTRAST         = const(0x81)
SET_ENTIRE_ON        = const(0xA4)
SET_NORM_INV         = const(0xA6)
SET_DISP             = const(0xAE)
SET_MEM_ADDR         = const(0x20)
SET_COL_ADDR         = const(0x21)
SET_PAGE_ADDR        = const(0x22)
SET_DISP_START_LINE  = const(0x40)
SET_SEG_REMAP        = const(0xA0)
SET_MUX_RATIO        = const(0xA8)
SET_COM_OUT_DIR      = const(0xC0)
SET_DISP_OFFSET      = const(0xD3)
SET_COM_PIN_CFG      = const(0xDA)
SET_DISP_CLK_DIV     = const(0xD5)
SET_PRECHARGE        = const(0xD9)
SET_VCOM_DESEL       = const(0xDB)
SET_CHARGE_PUMP      = const(0x8D)

class SSD1306:
    def __init__(self, width, height, external_vcc=False):
        self.width  = width
        self.height = height
        self.external_vcc = external_vcc
        self.pages = self.height // 8
        self.buffer = bytearray(self.pages * self.width)
        # MONO_VLSB = each byte is a vertical column of 8 pixels, LSB at top
        self.framebuf = framebuf.FrameBuffer(self.buffer, self.width, self.height, framebuf.MONO_VLSB)
        self.poweron()
        self.init_display()

    # FrameBuffer passthrough helpers
    def fill(self, c):              self.framebuf.fill(c)
    def pixel(self, x, y, c):       self.framebuf.pixel(x, y, c)
    def hline(self, x, y, w, c):    self.framebuf.hline(x, y, w, c)
    def vline(self, x, y, h, c):    self.framebuf.vline(x, y, h, c)
    def line(self, x1, y1, x2, y2, c): self.framebuf.line(x1, y1, x2, y2, c)
    def rect(self, x, y, w, h, c):  self.framebuf.rect(x, y, w, h, c)
    def fill_rect(self, x, y, w, h, c): self.framebuf.fill_rect(x, y, w, h, c)
    def text(self, s, x, y, c=1):   self.framebuf.text(s, x, y, c)
    def scroll(self, dx, dy):       self.framebuf.scroll(dx, dy)

    # Low-level stubs (implemented in subclass)
    def write_cmd(self, cmd):       raise NotImplementedError
    def write_data(self, buf):      raise NotImplementedError

    def poweroff(self):
        self.write_cmd(SET_DISP | 0x00)

    def poweron(self):
        self.write_cmd(SET_DISP | 0x01)

    def contrast(self, contrast):
        self.write_cmd(SET_CONTRAST)
        self.write_cmd(contrast)

    def invert(self, invert):
        self.write_cmd(SET_NORM_INV | (invert & 1))

    def init_display(self):
        # Initialization sequence (per SSD1306 datasheet)
        for cmd in (
            SET_DISP | 0x00,          # display off
            SET_MEM_ADDR, 0x00,       # horizontal addressing
            SET_DISP_START_LINE | 0x00,
            SET_SEG_REMAP | 0x01,     # column address 127 is mapped to SEG0
            SET_MUX_RATIO, self.height - 1,
            SET_COM_OUT_DIR | 0x08,   # scan from COM[N-1] to COM0
            SET_DISP_OFFSET, 0x00,
            SET_COM_PIN_CFG, 0x02 if self.height == 32 else 0x12,
            SET_DISP_CLK_DIV, 0x80,
            SET_PRECHARGE, 0x22 if self.external_vcc else 0xF1,
            SET_VCOM_DESEL, 0x30,     # 0.83*Vcc
            SET_CONTRAST, 0xFF if not self.external_vcc else 0x9F,
            SET_ENTIRE_ON,            # output follows RAM
            SET_NORM_INV,             # not inverted
            SET_CHARGE_PUMP, 0x10 if self.external_vcc else 0x14,
            SET_COL_ADDR, 0x00, self.width - 1,
            SET_PAGE_ADDR, 0x00, self.pages - 1,
            SET_DISP | 0x01           # display on
        ):
            self.write_cmd(cmd)
        self.fill(0)
        self.show()

    def show(self):
        # Update entire display from RAM buffer
        self.write_cmd(SET_COL_ADDR)
        self.write_cmd(0)
        self.write_cmd(self.width - 1)
        self.write_cmd(SET_PAGE_ADDR)
        self.write_cmd(0)
        self.write_cmd(self.pages - 1)
        # Write in chunks to avoid I2C buffer limits
        for i in range(0, len(self.buffer), 16):
            self.write_data(self.buffer[i:i+16])

class SSD1306_I2C(SSD1306):
    def __init__(self, width, height, i2c, addr=0x3C, external_vcc=False):
        self.i2c = i2c
        self.addr = addr
        self.temp = bytearray(2)  # command prefix buffer
        super().__init__(width, height, external_vcc)

    def write_cmd(self, cmd):
        # 0x80 = Co=1, D/C#=0 → command stream
        self.i2c.writeto(self.addr, bytes([0x80, cmd]))

    def write_data(self, buf):
        # 0x40 = Co=0, D/C#=1 → data stream
        # Prepend 0x40 then raw pixel bytes
        self.i2c.writeto(self.addr, b'\x40' + buf)
