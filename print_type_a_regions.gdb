set $i = 0
while ($i < memblock.reserved->cnt)
  printf "Region[%3d]: base=0x%-12lx, end=0x%-12lx, size=%-10.3f KB\n", \
         $i, \
         memblock.reserved->regions[$i].base, \
         memblock.reserved->regions[$i].base + memblock.reserved->regions[$i].size, \
         memblock.reserved->regions[$i].size / 1024.0
  set $i = $i + 1
end
set $i = 0
while ($i < memblock.memory->cnt)
  printf "Region[%3d]: base=0x%-12lx, end=0x%-12lx, size=%-10.3f KB\n", \
         $i, \
         memblock.memory->regions[$i].base, \
         memblock.memory->regions[$i].base + memblock.memory->regions[$i].size, \
         memblock.memory->regions[$i].size / 1024.0
  set $i = $i + 1
end