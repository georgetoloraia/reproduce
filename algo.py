import ecdsa
import binascii

def get_uncompressed_public_key(point):
    """აბრუნებს არაკომპრესირებულ საჯარო გასაღებს წერტილიდან (04 + x + y)."""
    x = point.x().to_bytes(32, byteorder='big')
    y = point.y().to_bytes(32, byteorder='big')
    return '04' + binascii.hexlify(x).decode('ascii') + binascii.hexlify(y).decode('ascii')

def get_x_coordinate_int(point):
    """აბრუნებს x-კოორდინატს, როგორც მთელი რიცხვი."""
    return point.x()

def read_allpubs(file_path):
    """კითხულობს allpubs.txt-ს და აბრუნებს (x, y) წყვილების სიას."""
    pairs = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    x, y = map(int, line.split(','))
                    pairs.append((x, y))
    except FileNotFoundError:
        print(f"ფაილი {file_path} ვერ მოიძებნა!")
        return []
    except ValueError:
        print(f"ფაილი {file_path} შეიცავს არასწორ ფორმატს! თითოეული ხაზი უნდა იყოს 'x,y'.")
        return []
    return pairs

def read_only_x(file_path):
    """კითხულობს only_x.txt-ს და აბრუნებს x-კოორდინატების სიას, როგორც მთელი რიცხვები."""
    x_coords = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    x_coords.append(int(line))
    except FileNotFoundError:
        print(f"ფაილი {file_path} ვერ მოიძებნა!")
        return []
    except ValueError:
        print(f"ფაილი {file_path} შეიცავს არასწორ ფორმატს! თითოეული ხაზი უნდა იყოს მთელი რიცხვი.")
        return []
    return x_coords

def main():
    # secp256k1 მრუდის განსაზღვრა
    curve = ecdsa.SECP256k1
    G = curve.generator  # გენერატორის წერტილი
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # secp256k1-ის ორდერი

    # 1. allpubs.txt-ის წაკითხვა
    pairs = read_allpubs("allpubs.txt")
    if not pairs:
        return

    # 2. only_x.txt-ის წაკითხვა
    only_x_coords = read_only_x("only_x.txt")
    if not only_x_coords:
        return

    # 3. თითოეული წყვილის დამუშავება
    for x1, y1 in pairs:
        for x2, y2 in pairs:
            # ორი შემთხვევის განხილვა: (n - x2) და (n - y2)
            for input_second_g, label in [(n - x2, "n - x2"), (n - y2, "n - y2")]:
                sum_mn = (x1 + input_second_g) % n  # (x1 + (n - x2)) % n ან (x1 + (n - y2)) % n
                if sum_mn == 0:  # თუ 0-ია, გამოტოვება (უსასრულობის წერტილი)
                    continue
                # გამოთვლა: (m + n) * G
                sumG = sum_mn * G
                sumG_x = get_x_coordinate_int(sumG)
                # შემოწმება: არის თუ არა sumG_x only_x.txt-ში
                if sumG_x in only_x_coords:
                    # mG და nG წერტილების გამოთვლა საჯარო გასაღებებისთვის
                    mG = x1 * G
                    mG_public_key = get_uncompressed_public_key(mG)
                    nG = input_second_g * G
                    nG_public_key = get_uncompressed_public_key(nG)
                    # შედეგების გამოტანა
                    print(f"დამთხვევა ნაპოვნია input_first_g = {x1}, input_second_g = {input_second_g} ({label}):")
                    print(f"    mG (m = {x1}) საჯარო გასაღები: {mG_public_key}")
                    print(f"    nG (n = {input_second_g}) საჯარო გასაღები: {nG_public_key}")
                    print(f"    (m + n)G (m + n = {sum_mn}) x-კოორდინატი: {sumG_x}")
                    print(f"    (m + n)G-ის x-კოორდინატი არის only_x.txt-ში? დიახ")

if __name__ == "__main__":
    main()