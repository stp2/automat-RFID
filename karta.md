# Rozvržení paměti
Data uložená v sektoru 1.
## Bloky
0(4) Jméno \
1(5) ID Value block. 4 byty se znaménkem. \
2(6) Obnos peněz. Value block. 4 byty se znaménkem. \
3(7) Trailer s oběma klíči

## Práva na bloky
0) 100
1) 110
2) 110
3) 011

Klíč B potřeba na zápis a increase. Klíč A zvládne jenom read a decrease.
