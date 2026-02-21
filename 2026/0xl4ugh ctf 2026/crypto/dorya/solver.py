from sage.all import *
# import json
# from Crypto.Util.number import long_to_bytes

# Given data (you'll need to replace this with actual output from the challenge)
# The output should be a list of dictionaries with 'n' and 'c' keys
# Example format: [{"n": 123..., "c": 456...}, ...]

# Load the output data
# with open("out.txt", "r") as f:
#     data = json.loads(f.read().replace("'", '"'))

# Constants
D = 2**1024
X = 7  # RSA exponent

# Initial coefficients as per the challenge
a0 = 1 * D
b0 = 3 * D
c0 = 3 * D
d0 = 7 * D

# Function to compute coefficients for each round
def get_coeffs(i):
    # Coefficients are updated as:
    # a += D, b += D^2, c += D * 3^1024, d += D^3
    a = a0 + i * D
    b = b0 + i * D**2
    c = c0 + i * D * (3**1024)
    d = d0 + i * D**3
    return a, b, c, d

# Extract n_i and ct_i from data
# n_list = [item['n'] for item in data]
# ct_list = [item['c'] for item in data]

n_list = [118636480445922997414990601093376262738873200793785339179564817109865454031931486586508946517137468038918549130611281608407631797608189160613009202727333210449589813079603946610204369133692321049079826961684843062183608289281070542325771713618963848998628576932902235933106794937930673264643682434933057492433, 131160321902858034841195946938587017781997161308396862773956654416182691939545448551857388576410043798733288287837052640260945663532662267195108018395040803240305121769245565408637762492271957738418122662994981028803288381639946388912455621131447118348550446244845844206461398471999028867216191468136089680143, 154830818659483193737573927783875495646379633764394616547958627049179457167548322011574199885671750299005783897829650885485542781631803942943198898586924991542905469204731741795576025398513971760645590562069187548084404736992464019389528352924062509716238147876187297587762062038926791406887518063921770301473, 126468349946801322536391681030075730288378558576364706877510756048167999402408960586406881204133573620526272880655567379876443683695992936297143676128295482911786962499451443709092614941904048804183338936433695318540282316857227805251535631063667438037518413081242484582029879339195049160568539967769398464097, 107965093573045452876348823513575859160292383466765405818823723508876908127695629453839323597794623586752827054791457505581350211011278156105556590516432960298779139201051898038871560876270229657032048184166916715065247210443627961168039821537885604993000471536658679313291015971624139433231797556540878305459, 155864629020615274595439354579800934345617446763583728691408321400203137117655118765146411529699993257076966511592331502990934719511342903426345867469892965823802034340672902732259358497811063092473100444924528723252464749725711538022994029677159555368989847392410006872989201761569578038249287465970750084973, 135172021455524150863031129279056313881418393925273837990929953123274650022032073006377347222128419434319543283529434256245838061359305930901003153448494115064736953512544441729296343283703162067270546102796199642359426870960722952443781942799975040685852772801272293259149167266897571490219346447956073174487]
ct_list = [85245911405166612359858091783054881795731056510112601911606301947571291279154016120081154880734315849097920140655909625901956711124236650532809801624318091766720604993267558138969488943103164261298759313955791149617121427046412247417646539270303396702168129740700024701970789126704213360948160444564937912612, 35804479868607566902211673402022249946214239861248697465302478835944656343996293771210848054187864641535637743394957165170659114057997850639797394251900053953875165772296140112854365369226546874053409170114767791986824783027031041543034569244146708448292399054640458362108335724536870970802411915691113123324, 94523484106485459257596608338431794285639635380170165773396432707021490637944324565165032018247376422108736105207188523021140840184329193495294155220465609055530241441661308977033813759916254044969612380689812890622012658376623785736725057231382628206618041139594089917368619973914165476386629791146437342539, 56059150362957976476682778635353295193028938541439873093359391724457503844424826664614935677699255212353734841553470999440180680668638279222562262258319962548766852889563670301878183236548787626133150230295070109625659435956631799262307267231071014742313063967839945790247260951497924388036041405405204350890, 10507898382811701875118745080984834009415198095825193518179981849776230136474778273851890738987810919194314178613523190561149223516706015650256128168505814857296683994128279557011350670505048347767957078972347126229032041707055626954036185938915629108695901983583359446294357905928614851930696491116206317833, 124059959667742311513931416359915086307231146589814428244593903341315050638141174587302919686846859730845400018546317174827240147706314075769876020878156195054620173347136842263280972314204859731214455876239163403604934487729064737031918124285859551305306519451430127509113033463774819587646867696127897558856, 91068725264420794942213585947434809008200784683554198551440546980770261872873464867051469100706192251136693399449091142767868507994139953882370575148485778448778426359718253567526100055834491969372020619710918929753113758589388319770093477393104197325057662249580727785486189205788292104666763170042419943171]

# Compute CRT modulus N
N = prod(n_list)

# We'll build the polynomial coefficients using CRT
# The polynomial is: (a_i*m + b_i)^7 - ct_i*(c_i*m + d_i)^7 ≡ 0 mod n_i

# Initialize lists to store polynomial coefficients for each modulus
poly_coeffs_mod_n = []
for i in range(7):
    a, b, c, d = get_coeffs(i)
    n = n_list[i]
    ct = ct_list[i]
    
    # Reduce coefficients modulo n to avoid huge intermediate values
    a_mod = a % n
    b_mod = b % n
    c_mod = c % n
    d_mod = d % n
    
    # Build the polynomial: (a*x + b)^7 - ct*(c*x + d)^7
    # We'll compute coefficients for x^0 to x^7
    coeffs = [0]*8
    
    # Compute (a*x + b)^7 coefficients
    for k in range(8):
        coeff = binomial(7, k) * (a_mod**k) * (b_mod**(7-k))
        coeffs[k] = coeff % n
    
    # Subtract ct*(c*x + d)^7 coefficients
    for k in range(8):
        coeff = binomial(7, k) * (c_mod**k) * (d_mod**(7-k))
        coeffs[k] = (coeffs[k] - ct * coeff) % n
    
    poly_coeffs_mod_n.append(coeffs)

# Now combine coefficients using CRT
final_coeffs = [0]*8
for k in range(8):
    # Collect the k-th coefficient from each polynomial
    residues = [poly_coeffs_mod_n[i][k] for i in range(7)]
    # Use CRT to combine
    final_coeffs[k] = crt(residues, n_list)

# Create the polynomial F(x) modulo N
R.<x> = PolynomialRing(Zmod(N))
F = sum(final_coeffs[k] * x**k for k in range(8))

# Make the polynomial monic if possible
# Check if leading coefficient is invertible modulo N
leading_coeff = final_coeffs[7]
if gcd(leading_coeff, N) == 1:
    F = F * inverse_mod(leading_coeff, N)
else:
    # If not invertible, we might need to handle differently
    # But this is unlikely for RSA moduli
    print("Warning: Leading coefficient not invertible modulo N")
    # Try to find a factor of N
    g = gcd(leading_coeff, N)
    if g != 1 and g != N:
        print(f"Found factor: {g}")
        # We could work modulo this factor instead
        # But for now, let's continue with the original approach

# Use Coppersmith to find small roots
# The flag is about 54 bytes = 432 bits
# We use a bound slightly larger than 2^432 to be safe
bound = 2**450

# We need to use small_roots with appropriate parameters
# First, let's try the standard Coppersmith method
roots = F.small_roots(X=bound, beta=0.5, epsilon=0.05)

if roots:
    m = roots[0]
    print(f"Found root: {m}")
    print(f"As bytes: {(int(m))}")
    # print(f"As bytes: {long_to_bytes(int(m))}")
else:
    print("No small roots found with standard parameters")
    
    # Try with different parameters
    print("Trying with different epsilon...")
    for epsilon in [0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1]:
        roots = F.small_roots(X=bound, beta=0.5, epsilon=epsilon)
        if roots:
            m = roots[0]
            print(f"Found root with epsilon={epsilon}: {m}")
            # print(f"As bytes: {long_to_bytes(int(m))}")
            print(f"As bytes: {(int(m))}")
            break
    
    if not roots:
        print("Still no roots found. Trying alternative approach...")
        
        # Alternative: Use resultants or LLL directly
        # Since we have 7 equations, we can try to find a solution modulo the product
        # Another approach: Use Gröbner basis on the 7 equations
        
        # Let's try to solve the system of congruences directly
        # We have 7 equations: F_i(m) ≡ 0 mod n_i
        # We can find m modulo N using CRT on the roots of each polynomial
        
        # For each modulus, find potential roots modulo that modulus
        all_roots = []
        for i in range(7):
            # Create polynomial modulo n_i
            ni = n_list[i]
            Ri.<x> = PolynomialRing(Zmod(ni))
            coeffs_i = poly_coeffs_mod_n[i]
            Fi = sum(coeffs_i[k] * x**k for k in range(8))
            
            # Find roots modulo n_i
            # Note: This might be slow for large modulus
            try:
                roots_mod_ni = Fi.roots(multiplicities=False)
                all_roots.append([int(r) for r in roots_mod_ni])
                print(f"Modulus {i}: Found {len(roots_mod_ni)} potential roots")
            except:
                print(f"Modulus {i}: Error finding roots")
                # If we can't find all roots, we might need a different approach
        
        # If we found roots for all moduli, try all combinations
        if all(all_roots):
            print("Trying all combinations of roots...")
            # This could be computationally expensive if there are many roots
            # But typically there shouldn't be too many
            from itertools import product
            
            for combo in product(*all_roots):
                try:
                    m_candidate = crt(list(combo), n_list)
                    # Check if it's a valid flag
                    flag_candidate = long_to_bytes(m_candidate)
                    if b'0xL4ugh{' in flag_candidate:
                        print(f"Found flag: {flag_candidate}")
                        break
                except:
                    continue