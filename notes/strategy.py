
# From https://crypto.stackexchange.com/questions/58375/how-to-get-an-optimal-strategy-in-computing-isogenies-for-sidh-sike/58377#58377
# n is generally (e//2) - 1, p the cost of two xDBL and q the cost of computing+evaluting a 4-isogeny
def strategy(n, p, q):
    S = { 1: [] }
    C = { 1: 0 }
    for i in range(2, n+2):
        b, cost = min(((b, C[i-b] + C[b] + b*p + (i-b)*q) for b in range(1,i)),
                      key=lambda t: t[1])
        S[i] = [b] + S[i-b] + S[b]
        C[i] = cost
    return S[n+1]

# Strategy for Alice
print('Alice ', str(strategy(54, 2 * 684, 430 + 905)))
#Strategy Bob
print('Bob ', str(strategy(66, 1366, 618+654)))

#TODO: Strategy Attacker