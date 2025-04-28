import piheaan as heaan
import numpy as np
import os


class MusicRevenueAnalyzer:
    def __init__(self, log_slots=15, key_dir="./keys"):
        self.log_slots = log_slots
        self.num_slots = 1 << log_slots
        self.key_dir = key_dir

        print("Setting up context...")
        self.params = heaan.ParameterPreset.FGb
        self.context = heaan.make_context(self.params)

        try:
            heaan.make_bootstrappable(self.context)
            print("Context configured for bootstrapping (enables more operations)")
        except Exception as e:
            print(
                f"Warning: Error during bootstrapping setup (proceeding anyway): {e}")

        os.makedirs(self.key_dir, mode=0o775, exist_ok=True)

        print("Generating keys...")
        self.sk = heaan.SecretKey(self.context)
        self.key_generator = heaan.KeyGenerator(self.context, self.sk)
        self.key_generator.gen_common_keys()
        self.key_pack = self.key_generator.keypack
        print("Key generation completed.")

        print("Initializing encryptor, decryptor, and evaluator...")
        self.enc = heaan.Encryptor(self.context)
        self.dec = heaan.Decryptor(self.context)
        self.eval = heaan.HomEvaluator(self.context, self.key_pack)
        print("Initialization completed.")

    def encrypt_revenue_data(self, data, metadata):
        if len(data) > self.num_slots:
            raise ValueError(
                f"Data count({len(data)}) exceeds slot capacity({self.num_slots}). "
                f"Increase log_slots or split data.")

        message = heaan.Message(self.log_slots)
        for i in range(len(data)):
            message[i] = float(data[i])

        ciphertext = heaan.Ciphertext(self.context)
        self.enc.encrypt(message, self.key_pack, ciphertext)

        return {
            "encrypted_data": ciphertext,
            "metadata": metadata
        }

    def calculate_average(self, encrypted_data_list, filter_criteria=None):
        filtered_encrypted_ciphertexts = []
        if filter_criteria:
            print(f"Applying filter criteria: {filter_criteria}")
            for item in encrypted_data_list:
                matches = True
                for key, value in filter_criteria.items():
                    if item["metadata"].get(key) != value:
                        matches = False
                        break
                if matches:
                    filtered_encrypted_ciphertexts.append(
                        item["encrypted_data"])
        else:
            print("No filter criteria - using all data")
            filtered_encrypted_ciphertexts = [
                item["encrypted_data"] for item in encrypted_data_list]

        num_filtered = len(filtered_encrypted_ciphertexts)
        print(f"Number of ciphertexts for average calculation: {num_filtered}")

        if not filtered_encrypted_ciphertexts:
            return None

        sum_encrypted_data = heaan.Ciphertext(self.context)

        if filtered_encrypted_ciphertexts:
            self.eval.mult(
                filtered_encrypted_ciphertexts[0], 1.0, sum_encrypted_data)

        for i in range(1, num_filtered):
            self.eval.add(sum_encrypted_data,
                          filtered_encrypted_ciphertexts[i], sum_encrypted_data)

        if num_filtered > 0:
            average_divisor = 1.0 / num_filtered
            self.eval.mult(sum_encrypted_data, average_divisor,
                           sum_encrypted_data)

        return sum_encrypted_data

    def decrypt_result(self, encrypted_result, num_elements=None):
        if not isinstance(encrypted_result, heaan.Ciphertext):
            raise TypeError(
                "Decryption target must be a heaan.Ciphertext object")

        result_message = heaan.Message(self.log_slots)
        self.dec.decrypt(encrypted_result, self.sk, result_message)

        if num_elements is None:
            effective_num_elements = self.num_slots
        else:
            effective_num_elements = min(num_elements, self.num_slots)

        result_list = []
        try:
            for i in range(effective_num_elements):
                result_list.append(result_message[i].real)
        except IndexError:
            print(f"Warning: Index error at {i} - returning partial results")
            pass
        except Exception as e:
            print(f"Unexpected error during result extraction: {e}")
            pass

        return result_list

# --- 사용 예시 ---


def main():
    """Simulates the actual analysis process using the MusicRevenueAnalyzer class."""
    print("=== Starting Music Revenue Analysis System Demo ===")

    # 1. Initialize analyzer (Create Context, generate keys, etc.)
    try:
        # log_slots=15 means 2^15 = 32,768 slots
        # This allows storing over 30,000 data points in a single ciphertext
        # It's common to set this much larger than the actual data requirement
        analyzer = MusicRevenueAnalyzer(log_slots=15)
    except Exception as e:
        print(f"Critical error during analyzer initialization: {e}")
        return  # Abort if initialization fails

    # 2. Prepare sample data
    # In real scenarios, each musician (client) would have their own data
    # Revenue data is assumed to be normalized (e.g., 150.0 = 1,500,000 KRW / 10,000 KRW)
    musician1_data_raw = {
        # Quarterly revenue (Q1: 1.5M KRW, Q2: 2M KRW, Q3: 1.8M KRW, Q4: 2.5M KRW)
        "revenue": [150.0, 200.0, 180.0, 250.0],
        # Genre: pop, Experience: 3 years
        "metadata": {"genre": "pop", "experience": 3}
    }
    musician2_data_raw = {
        "revenue": [120.0, 130.0, 140.0, 150.0],  # Q1-Q4 revenue
        # Genre: rock, Experience: 2 years
        "metadata": {"genre": "rock", "experience": 2}
    }
    musician3_data_raw = {
        "revenue": [180.0, 220.0, 190.0, 280.0],  # Q1-Q4 revenue
        # Genre: pop, Experience: 5 years
        "metadata": {"genre": "pop", "experience": 5}
    }

    # 3. Encrypt data
    # Each musician's data is encrypted individually
    # This should be done on each musician's device or in a trusted environment
    # The server only receives encrypted data. Here we simulate this process in one place.
    print("\n--- Encrypting musician data ---")
    all_encrypted_data = []  # List to store encrypted results
    try:
        encrypted_musician1 = analyzer.encrypt_revenue_data(
            musician1_data_raw["revenue"], musician1_data_raw["metadata"])
        all_encrypted_data.append(encrypted_musician1)
        print("Musician 1 data encrypted successfully.")

        encrypted_musician2 = analyzer.encrypt_revenue_data(
            musician2_data_raw["revenue"], musician2_data_raw["metadata"])
        all_encrypted_data.append(encrypted_musician2)
        print("Musician 2 data encrypted successfully.")

        encrypted_musician3 = analyzer.encrypt_revenue_data(
            musician3_data_raw["revenue"], musician3_data_raw["metadata"])
        all_encrypted_data.append(encrypted_musician3)
        print("Musician 3 data encrypted successfully.")
    except ValueError as ve:  # Possible errors from encrypt_revenue_data
        print(f"Encryption error: {ve}")
        return
    except Exception as e:
        print(f"Unexpected encryption error: {e}")
        return

    # 4. Perform encrypted statistical calculations (e.g., genre-based average revenue)
    # The server/analyst performs operations on encrypted data
    # The server cannot see any original revenue values
    print("\n--- Calculating genre-based average revenue (on encrypted data) ---")
    # Filter and calculate average for pop genre
    pop_filter = {"genre": "pop"}
    pop_average_encrypted = analyzer.calculate_average(
        all_encrypted_data, pop_filter)

    # Filter and calculate average for rock genre
    rock_filter = {"genre": "rock"}
    rock_average_encrypted = analyzer.calculate_average(
        all_encrypted_data, rock_filter)

    # 5. Decrypt and display results
    # The secret key holder decrypts the results
    print("\n--- Decrypting and displaying results ---")
    num_quarters = 4  # Original data had 4 quarters

    # Decrypt pop genre average
    if pop_average_encrypted:
        try:
            decrypted_pop_average = analyzer.decrypt_result(
                pop_average_encrypted, num_elements=num_quarters)
            print("Pop Genre Quarterly Average Revenue (Decrypted):")
            # Convert back to original unit (KRW)
            for i, avg in enumerate(decrypted_pop_average):
                print(f"  Q{i+1}: {avg * 10000:,.0f} KRW")
        except Exception as e:
            print(f"Pop average decryption error: {e}")
    else:
        print("No data found for pop genre or calculation failed.")

    # Decrypt rock genre average
    if rock_average_encrypted:
        try:
            decrypted_rock_average = analyzer.decrypt_result(
                rock_average_encrypted, num_elements=num_quarters)
            print("\nRock Genre Quarterly Average Revenue (Decrypted):")
            for i, avg in enumerate(decrypted_rock_average):
                print(f"  Q{i+1}: {avg * 10000:,.0f} KRW")
        except Exception as e:
            print(f"Rock average decryption error: {e}")
    else:
        print("\nNo data found for rock genre or calculation failed.")

    print("\n=== Music Revenue Analysis System Demo Completed ===")


if __name__ == "__main__":
    main()
