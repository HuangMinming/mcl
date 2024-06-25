
def getMontgomeryCoeff(pLow, W):
  pp = 0
  t = 0
  x = 1
  for i in range(W):
    if t % 2 == 0:
      t += pLow
      pp += x
    t >>= 1
    x <<= 1
  return pp

class Montgomery:
  def __init__(self, p, W=52, N=8):
    self.p = p
    self.W = W
    self.N = N
    self.mask = (1<<W)-1
    self.R = 2**(W*N) % p
    self.R2 = self.R**2 % p
    self.rp = getMontgomeryCoeff(p & self.mask, W)
  def put(self):
    print(f'''p={hex(self.p)}
W={self.W}
N={self.N}
mask={hex(self.mask)}
R={hex(self.R)}
R2={hex(self.R2)}
rp={hex(self.rp)}''')

class BLS12:
  def __init__(self, z=-0xd201000000010000):
    self.M = 1<<256
    self.H = 1<<128
    self.z = z
    self.L = self.z**2 - 1
    self.r = self.L*(self.L+1) + 1
    self.p = (z-1)**2*self.r//3 + z

def putCode(curve, mont):
  print(f'''static const uint64_t g_mask = {hex(mont.mask)};
static const uint64_t g_vmask_[] = {{ {"g_mask, "*8}}};

struct G {{
	static const Vec& vmask() {{ return *(const Vec*)g_vmask_; }}
}};
''')

def main():
  curve = BLS12()

  mont = Montgomery(curve.p)
#  mont.put()
  putCode(curve, mont)

if __name__ == '__main__':
  main()

