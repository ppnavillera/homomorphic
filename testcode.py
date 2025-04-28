import piheaan as heaan  # pi-heaan 라이브러리 임포트 (CKKS 동형암호 구현체)
# 수치 계산, 특히 배열 처리에 사용 (여기서는 명시적으로 많이 사용되진 않으나, HE에서 자주 함께 사용됨)
import numpy as np
import os          # 운영체제 기능 사용 (파일 경로 생성 등)


class MusicRevenueAnalyzer:
    """
    음악 창작자를 위한 익명 수익 분석 시스템
    CKKS 동형 암호화를 사용하여 개인 수익 데이터를 보호하면서 통계 분석 (평균 등)을 수행합니다.
    개별 데이터는 암호화되어 서버/분석가는 원본 값을 볼 수 없지만,
    암호화된 상태에서 합산, 평균 등의 연산을 수행할 수 있습니다.
    """

    def __init__(self, log_slots=15, key_dir="./keys"):
        """
        CKKS 암호화 환경을 초기화하고 필요한 키를 생성합니다.

        Args:
            log_slots (int): 암호문(Ciphertext) 하나에 담을 수 있는 값(슬롯)의 개수를 로그 스케일로 지정합니다.
                             실제 슬롯 수는 2^log_slots 가 됩니다. (예: 15 -> 32768개 슬롯)
                             슬롯 수가 클수록 한 번에 많은 데이터를 처리할 수 있지만, 연산 속도가 느려지고 메모리 사용량이 증가합니다.
            key_dir (str): 생성된 키 파일들(여기서는 직접 파일 저장 안 함)이나 관련 설정 파일을 저장할 디렉토리 경로입니다.
                           (현재 코드에서는 KeyPack 객체로 메모리에 유지)
        """
        # --- 파라미터 설정 ---
        self.log_slots = log_slots
        self.num_slots = 1 << log_slots  # 실제 슬롯 개수 계산 (2의 거듭제곱)
        self.key_dir = key_dir

        print("Context 설정 중...")
        self.params = heaan.ParameterPreset.FGb
        self.context = heaan.make_context(self.params)

        # --- 부트스트래핑 설정 ---
        try:
            heaan.make_bootstrappable(self.context)
            print("Context가 부트스트래핑 가능하게 설정되었습니다. (더 많은 연산 가능)")
        except Exception as e:
            # 부트스트래핑 설정이 실패할 수도 있습니다 (라이브러리 버전, 시스템 환경 등에 따라).
            # 실패하더라도 기본적인 연산(덧셈, 상수 곱셈 등)은 가능하므로 경고만 출력하고 진행합니다.
            print(f"경고: 부트스트래핑 설정 중 오류 발생 (무시하고 진행): {e}")

        # --- 키 디렉토리 생성 ---
        # 키 파일 등을 저장할 디렉토리가 없으면 생성합니다.
        os.makedirs(self.key_dir, mode=0o775, exist_ok=True)

        # --- 키 생성 ---
        print("키 생성 중...")
        # 비밀키(Secret Key, sk): 데이터 복호화에 사용되는 유일한 키입니다. **절대 외부에 노출되어서는 안 됩니다.**
        # 시스템 설계상, 이 키는 최종 결과 확인이 필요한 신뢰된 사용자(또는 분산된 키 관리 시스템)만 접근 가능해야 합니다.
        self.sk = heaan.SecretKey(self.context)

        # 키 생성기(Key Generator): 비밀키를 기반으로 다른 필요한 키들을 생성하는 객체입니다.
        self.key_generator = heaan.KeyGenerator(self.context, self.sk)
        # 공개키(Public Key) 생성
        # - 공개키: 데이터를 암호화할 때 사용됩니다. 비밀키 없이 공개키만으로 암호화 가능.
        # - 부트스트래핑 키: 부트스트래핑 연산을 위해 필요합니다. (make_bootstrappable 시 내부적으로 생성될 수 있음)
        self.key_generator.gen_common_keys()

        # KeyPack: 암호화 및 동형 연산(평가)에 필요한 키 등을 하나로 묶은 객체입니다.
        # 이 객체는 비밀키(sk)를 포함하지 않으므로, 데이터를 암호화하거나 암호문 연산을 수행하는 서버 등에 안전하게 배포될 수 있습니다.
        self.key_pack = self.key_generator.keypack  # KeyGenerator로부터 KeyPack 추출
        print("키 생성이 완료되었습니다.")

        # --- 암호화, 복호화, 평가 객체 생성 ---
        print("암호화기, 복호화기, 평가기 초기화 중...")
        # 암호화기(Encryptor): 메시지(평문 데이터)를 암호문으로 변환합니다. Context가 필요합니다.
        self.enc = heaan.Encryptor(self.context)
        # 복호화기(Decryptor): 암호문을 메시지(평문 데이터)로 변환합니다. Context가 필요합니다. 복호화 시에는 비밀키(sk)가 필요합니다.
        self.dec = heaan.Decryptor(self.context)
        # 동형 평가기(Homomorphic Evaluator): 암호문 상태에서 덧셈, 곱셈, 회전 등의 연산을 수행합니다.
        # Context와 함께 연산에 필요한 키들(KeyPack)이 필요합니다.
        self.eval = heaan.HomEvaluator(self.context, self.key_pack)
        print("초기화가 완료되었습니다.")

    def encrypt_revenue_data(self, data, metadata):
        """
        사용자로부터 받은 수익 데이터(리스트)와 관련 메타데이터를 받아서,
        수익 데이터를 CKKS 암호문으로 암호화합니다.

        Args:
            data (list): 암호화할 실수 값들의 리스트 (예: [150.0, 200.0, 180.0, 250.0]).
                         주의: 리스트의 길이는 self.num_slots 보다 작거나 같아야 합니다.
            metadata (dict): 데이터에 대한 부가 정보 (예: {"genre": "pop", "experience": 3}).
                             이 정보는 암호화되지 않고 그대로 유지되어 필터링 등에 사용됩니다.

        Returns:
            dict: 암호화된 데이터('encrypted_data')와 원본 메타데이터('metadata')를 포함하는 딕셔너리.
                  {'encrypted_data': Ciphertext 객체, 'metadata': 원본 dict}
        """
        # --- 입력 데이터 검증 ---
        # CKKS 암호문은 고정된 수의 슬롯을 가지므로, 입력 데이터의 개수가 슬롯 수를 초과할 수 없습니다.
        if len(data) > self.num_slots:
            raise ValueError(
                f"데이터 개수({len(data)})가 슬롯 개수({self.num_slots})보다 많습니다. log_slots를 늘리거나 데이터 분할이 필요합니다.")

        # --- 메시지 객체 생성 및 데이터 인코딩 ---
        # Message 객체는 HEaaN에서 평문 데이터를 암호화하기 전의 형태로 표현하는 데 사용됩니다.
        # log_slots를 인자로 주어 암호화될 슬롯의 크기에 맞게 생성합니다.
        message = heaan.Message(self.log_slots)

        # 입력받은 데이터 리스트의 각 요소를 Message 객체의 슬롯에 순서대로 할당합니다.
        # CKKS는 주로 실수(또는 복소수) 위에서 연산하므로 float 형태로 변환합니다.
        for i in range(len(data)):
            message[i] = float(data[i])
        # 참고: data 리스트의 길이보다 슬롯 수가 더 많으면, 나머지 슬롯들은 기본적으로 0으로 채워집니다.
        # HEaaN 내부 인코딩 과정에서 스케일링(적절한 2의 거듭제곱 곱하기)이 자동으로 수행됩니다.

        # --- 암호화 수행 ---
        # Ciphertext 객체를 생성합니다. 이 객체가 암호화된 데이터를 담게 됩니다.
        ciphertext = heaan.Ciphertext(self.context)
        # 암호화기(self.enc)를 사용하여 Message 객체를 암호화합니다.
        # 이 과정에서는 공개키 등이 포함된 KeyPack(self.key_pack)이 사용됩니다.
        # **중요: 비밀키(self.sk)는 암호화 과정에 사용되지 않습니다.** 따라서 KeyPack만 있다면 누구나 데이터를 암호화할 수 있습니다.
        # 결과는 ciphertext 객체에 저장됨
        self.enc.encrypt(message, self.key_pack, ciphertext)

        # 암호화된 데이터(Ciphertext 객체)와 원본 메타데이터를 딕셔너리 형태로 묶어 반환합니다.
        # 메타데이터는 필터링 등 분석 조건에 사용하기 위해 암호화하지 않고 그대로 전달합니다.
        return {
            "encrypted_data": ciphertext,  # 실제 암호문
            "metadata": metadata          # 암호화되지 않은 부가 정보
        }

    def calculate_average(self, encrypted_data_list, filter_criteria=None):
        """
        여러 개의 암호화된 수익 데이터 딕셔너리 리스트를 받아,
        필요시 메타데이터 기준으로 필터링한 후, 암호화된 상태에서 평균을 계산합니다.

        Args:
            encrypted_data_list (list): `encrypt_revenue_data` 함수의 반환값(딕셔너리)들로 이루어진 리스트.
                                        각 딕셔너리는 'encrypted_data' (Ciphertext)와 'metadata' (dict)를 포함합니다.
            filter_criteria (dict, optional): 특정 조건에 맞는 데이터만 필터링할 기준.
                                              예: {"genre": "pop", "season": "spring"}.
                                              None이면 모든 데이터를 사용합니다.

        Returns:
            heaan.Ciphertext or None: 계산된 평균 값의 암호문(Ciphertext 객체).
                                      필터링 결과 데이터가 없으면 None을 반환합니다.
        """
        # --- 데이터 필터링 ---
        filtered_encrypted_ciphertexts = []  # 필터링된 Ciphertext 객체만 저장할 리스트
        if filter_criteria:
            print(f"필터링 기준 적용: {filter_criteria}")
            # 전체 암호화된 데이터 리스트를 순회
            for item in encrypted_data_list:
                matches = True  # 현재 아이템이 모든 필터 조건을 만족하는지 여부
                # 필터 기준 딕셔너리의 각 키-값 쌍에 대해 검사
                for key, value in filter_criteria.items():
                    # 현재 아이템의 메타데이터에 해당 키가 없거나 값이 다르면 조건을 만족하지 않음
                    if item["metadata"].get(key) != value:
                        matches = False
                        break  # 하나라도 만족하지 않으면 더 검사할 필요 없음
                # 모든 필터 조건을 만족했다면, 해당 아이템의 암호문('encrypted_data')만 리스트에 추가
                if matches:
                    filtered_encrypted_ciphertexts.append(
                        item["encrypted_data"])
        else:
            # 필터 기준이 없으면 모든 데이터의 암호문을 사용
            print("필터링 기준 없음. 모든 데이터 사용.")
            filtered_encrypted_ciphertexts = [
                item["encrypted_data"] for item in encrypted_data_list]

        num_filtered = len(filtered_encrypted_ciphertexts)
        print(f"평균 계산 대상 암호문 개수: {num_filtered}")

        # 필터링 결과 데이터가 없으면 평균 계산 불가
        if not filtered_encrypted_ciphertexts:
            return None

        # --- 암호화된 상태에서의 합계 계산 ---
        # 결과를 저장할 새로운 Ciphertext 객체 생성
        sum_encrypted_data = heaan.Ciphertext(self.context)

        # 합계 초기화: 첫 번째 암호문으로 초기화합니다.
        # 주의: 그냥 할당하면 안 되고, 동형 연산을 사용해야 합니다.
        # 여기서는 첫 번째 암호문에 상수 1.0을 곱하는 방식으로 복사/초기화를 수행합니다.
        # CKKS는 복소수를 다루지만, 보통 실수 연산이 필요하므로 float 1.0을 사용합니다.
        # heaan.HomEvaluator.mult는 암호문과 상수(plain)의 곱셈을 지원합니다.
        if filtered_encrypted_ciphertexts:  # 리스트가 비어있지 않은지 한번 더 확인
            # self.eval.add(sum_encrypted_data, filtered_encrypted_ciphertexts[0], sum_encrypted_data) # 0 + 첫번째 데이터 -> 첫번째 데이터. 도 가능.
            # 아래는 상수 곱셈을 이용한 초기화/복사 방식.
            # sum_encrypted_data = filtered_encrypted_ciphertexts[0] * 1.0
            self.eval.mult(
                filtered_encrypted_ciphertexts[0], 1.0, sum_encrypted_data)

        # 나머지 암호문들을 누적하여 더합니다.
        # heaan.HomEvaluator.add는 두 암호문 간의 덧셈을 수행합니다.
        # sum_encrypted_data = sum_encrypted_data + filtered_encrypted_ciphertexts[i] 와 동일한 연산.
        for i in range(1, num_filtered):
            # 결과는 다시 sum_encrypted_data에 저장
            self.eval.add(sum_encrypted_data,
                          filtered_encrypted_ciphertexts[i], sum_encrypted_data)

        # --- 암호화된 상태에서의 평균 계산 (상수 곱셈 이용) ---
        # 합계를 데이터 개수로 나누어야 평균이 됩니다.
        # 동형암호에서는 암호문끼리의 나눗셈이 직접 지원되지 않거나 매우 복잡합니다.
        # 대신, '데이터 개수의 역수(1/N)'라는 *상수*를 암호화된 합계에 곱하는 방식으로 평균을 계산합니다.
        if num_filtered > 0:
            # 나눌 값(데이터 개수)의 역수를 계산 (실수)
            average_divisor = 1.0 / num_filtered
            # 암호화된 합계(sum_encrypted_data)에 상수(average_divisor)를 곱합니다.
            # self.eval.mult(암호문, 상수, 결과저장암호문)
            self.eval.mult(sum_encrypted_data, average_divisor,
                           sum_encrypted_data)  # 결과는 다시 sum_encrypted_data에 저장

        # 최종적으로 계산된 (암호화된) 평균 값을 반환합니다.
        return sum_encrypted_data

    def decrypt_result(self, encrypted_result, num_elements=None):
        """
        동형 연산의 최종 결과인 암호문(Ciphertext)을 복호화하여
        원래의 평문 값(실수 리스트)으로 되돌립니다.

        Args:
            encrypted_result (heaan.Ciphertext): 복호화할 암호문 객체. `calculate_average` 등의 결과물.
            num_elements (int, optional): 암호문 슬롯 중에서 실제로 의미있는 데이터가 담긴 앞부분의 개수.
                                         None이면 모든 슬롯(self.num_slots)에서 값을 추출하려고 시도합니다.

        Returns:
            list: 복호화된 실수 값들의 리스트.
        """
        # 입력 타입 검증
        if not isinstance(encrypted_result, heaan.Ciphertext):
            raise TypeError("복호화 대상은 heaan.Ciphertext 객체여야 합니다.")

        # 복호화 결과를 담을 Message 객체 생성 (암호화 전의 평문 형태)
        result_message = heaan.Message(self.log_slots)
        # 복호화기(self.dec)를 사용하여 암호문(encrypted_result)을 복호화합니다.
        # **중요: 복호화에는 반드시 비밀키(self.sk)가 필요합니다.**
        # 따라서 이 메소드는 비밀키를 가진 주체만이 호출할 수 있습니다.
        self.dec.decrypt(encrypted_result, self.sk, result_message)

        # --- 복호화된 값 추출 ---
        # 복호화된 Message 객체에서 실제 숫자 값들을 추출합니다.
        # 몇 개의 슬롯에서 값을 가져올지 결정합니다.
        if num_elements is None:
            # 사용자가 개수를 지정하지 않으면, 이론상 최대 슬롯 수만큼 시도합니다.
            # 하지만 실제 유효 데이터는 그보다 적을 수 있습니다 (예: 평균 계산 시 입력 데이터 개수만큼만 유효).
            effective_num_elements = self.num_slots
        else:
            # 사용자가 지정한 개수와 최대 슬롯 수 중 작은 값을 사용합니다.
            effective_num_elements = min(num_elements, self.num_slots)

        result_list = []
        try:
            # 지정된 개수만큼 슬롯을 순회하며 값을 추출
            for i in range(effective_num_elements):
                # CKKS는 내부적으로 복소수를 사용합니다. 암호화 시 실수를 넣었더라도 복호화 결과는 복소수 형태일 수 있습니다.
                # 일반적으로 우리가 원하는 실수 값은 복소수의 실수부(real part)에 해당합니다.
                # 따라서 `.real` 속성을 사용하여 실수부만 추출합니다.
                result_list.append(result_message[i].real)
        except IndexError:
            # 이론적으로 Message 객체는 log_slots에 맞는 크기로 생성되므로 이 오류는 발생하지 않아야 합니다.
            # 만약 발생한다면 라이브러리 내부 문제나 예상치 못한 상황일 수 있습니다.
            print(f"경고: Message 객체에서 인덱스 {i} 접근 중 오류 발생. 현재까지 추출된 값만 반환합니다.")
            pass  # 현재까지 추출된 값으로 계속 진행
        except Exception as e:
            # 기타 예외 처리 (예: 복호화 실패로 인한 이상한 값 접근 시도 등)
            print(f"복호화 결과 추출 중 예기치 않은 오류 발생: {e}")
            # 오류 발생 시 빈 리스트 또는 부분 리스트가 반환될 수 있음
            pass

        return result_list

# --- 사용 예시 ---


def main():
    """MusicRevenueAnalyzer 클래스를 사용하여 실제 분석 과정을 시뮬레이션합니다."""
    print("=== 음악 수익 분석 시스템 데모 시작 ===")

    # 1. 분석기 초기화 (Context 생성, 키 생성 등)
    try:
        # log_slots=15는 2^15 = 32768개의 슬롯을 의미합니다.
        # 이는 3만개 이상의 데이터를 한 암호문에 담을 수 있음을 뜻합니다.
        # 실제 필요한 데이터 개수보다 충분히 크게 설정하는 것이 일반적입니다.
        analyzer = MusicRevenueAnalyzer(log_slots=15)
    except Exception as e:
        print(f"분석기 초기화 중 치명적 오류 발생: {e}")
        return  # 초기화 실패 시 더 이상 진행 불가

    # 2. 샘플 데이터 준비
    # 실제 시나리오에서는 각 뮤지션(클라이언트)이 자신의 데이터를 가지고 있을 것입니다.
    # 수익 데이터는 정규화되었다고 가정 (예: 150.0은 1,500,000원 / 10,000원)
    musician1_data_raw = {
        # 분기별 수익 (Q1: 150만원, Q2: 200만원, Q3: 180만원, Q4: 250만원)
        "revenue": [150.0, 200.0, 180.0, 250.0],
        "metadata": {"genre": "pop", "experience": 3}  # 장르: 팝, 경력: 3년
    }
    musician2_data_raw = {
        "revenue": [120.0, 130.0, 140.0, 150.0],  # Q1~Q4 수익
        "metadata": {"genre": "rock", "experience": 2}  # 장르: 락, 경력: 2년
    }
    musician3_data_raw = {
        "revenue": [180.0, 220.0, 190.0, 280.0],  # Q1~Q4 수익
        "metadata": {"genre": "pop", "experience": 5}  # 장르: 팝, 경력: 5년
    }

    # 3. 데이터 암호화
    # 각 뮤지션의 데이터를 개별적으로 암호화합니다.
    # 이 과정은 각 뮤지션의 기기 또는 신뢰할 수 있는 환경에서 수행되어야 합니다.
    # 서버는 암호화된 데이터만 받게 됩니다. 여기서는 시뮬레이션을 위해 한 곳에서 처리합니다.
    print("\n--- 각 뮤지션 데이터 암호화 중 ---")
    all_encrypted_data = []  # 암호화된 결과들을 저장할 리스트
    try:
        encrypted_musician1 = analyzer.encrypt_revenue_data(
            musician1_data_raw["revenue"], musician1_data_raw["metadata"])
        all_encrypted_data.append(encrypted_musician1)
        print("뮤지션 1 데이터 암호화 완료.")

        encrypted_musician2 = analyzer.encrypt_revenue_data(
            musician2_data_raw["revenue"], musician2_data_raw["metadata"])
        all_encrypted_data.append(encrypted_musician2)
        print("뮤지션 2 데이터 암호화 완료.")

        encrypted_musician3 = analyzer.encrypt_revenue_data(
            musician3_data_raw["revenue"], musician3_data_raw["metadata"])
        all_encrypted_data.append(encrypted_musician3)
        print("뮤지션 3 데이터 암호화 완료.")
    except ValueError as ve:  # 데이터 개수 초과 등 encrypt_revenue_data에서 발생 가능한 오류
        print(f"데이터 암호화 중 오류 발생: {ve}")
        return
    except Exception as e:  # 기타 예외
        print(f"데이터 암호화 중 예기치 않은 오류 발생: {e}")
        return

    # 4. 암호화된 상태에서 통계 계산 (예: 장르별 평균 수익)
    # 서버(또는 분석가)는 수집된 암호문 리스트(all_encrypted_data)를 가지고 연산을 수행합니다.
    # 서버는 원본 수익 값을 전혀 알 수 없습니다.
    print("\n--- 장르별 평균 수익 계산 (암호화된 상태에서 수행) ---")
    # 팝 장르 데이터만 필터링하여 평균 계산
    pop_filter = {"genre": "pop"}
    pop_average_encrypted = analyzer.calculate_average(
        all_encrypted_data, pop_filter)

    # 락 장르 데이터만 필터링하여 평균 계산
    rock_filter = {"genre": "rock"}
    rock_average_encrypted = analyzer.calculate_average(
        all_encrypted_data, rock_filter)

    # 5. 결과 복호화 및 출력
    # 계산된 암호화된 평균값(pop_average_encrypted, rock_average_encrypted)을
    # 비밀키를 가진 주체(예: 시스템 관리자 또는 결과 요청자)가 복호화하여 확인합니다.
    print("\n--- 계산 결과 복호화 및 출력 ---")
    num_quarters = 4  # 원본 데이터가 4분기였으므로, 결과도 4개의 슬롯에 해당 값이 들어있을 것으로 예상

    # 팝 장르 평균 복호화
    if pop_average_encrypted:  # 평균 계산이 성공적으로 이루어졌다면 (None이 아니라면)
        try:
            # 복호화 수행 (비밀키 필요)
            decrypted_pop_average = analyzer.decrypt_result(
                pop_average_encrypted, num_elements=num_quarters)
            print("팝(Pop) 장르 분기별 평균 수익 (복호화 결과):")
            # 결과를 원래 단위(원)로 변환하여 출력
            for i, avg in enumerate(decrypted_pop_average):
                # avg 값은 정규화된 값이므로 원래 단위로 되돌리기 위해 * 10000 을 해줍니다.
                # : ,.0f 는 천단위 콤마를 찍고 소수점 없이 출력하는 포맷팅입니다.
                print(f"  Q{i+1}: {avg * 10000:,.0f} 원")
        except Exception as e:
            # 복호화 과정에서 오류가 발생할 수 있습니다 (예: 노이즈가 너무 많아 복호화 실패)
            print(f"팝 평균 복호화 중 오류 발생: {e}")
    else:
        # calculate_average에서 필터링된 데이터가 없거나 다른 이유로 None이 반환된 경우
        print("팝 장르에 대한 데이터가 없거나 평균 계산에 실패했습니다.")

    # 락 장르 평균 복호화 (팝과 동일한 로직)
    if rock_average_encrypted:
        try:
            decrypted_rock_average = analyzer.decrypt_result(
                rock_average_encrypted, num_elements=num_quarters)
            print("\n락(Rock) 장르 분기별 평균 수익 (복호화 결과):")
            for i, avg in enumerate(decrypted_rock_average):
                print(f"  Q{i+1}: {avg * 10000:,.0f} 원")
        except Exception as e:
            print(f"락 평균 복호화 중 오류 발생: {e}")
    else:
        print("\n락 장르에 대한 데이터가 없거나 평균 계산에 실패했습니다.")

    print("\n=== 음악 수익 분석 시스템 데모 종료 ===")


if __name__ == "__main__":
    main()
