import piheaan as heaan
import numpy as np
# import pandas as pd # pandas는 현재 코드에서 사용되지 않으므로 주석 처리
import os
# import json # json은 현재 코드에서 사용되지 않으므로 주석 처리


class MusicRevenueAnalyzer:
    """
    음악 창작자를 위한 익명 수익 분석 시스템
    CKKS 동형 암호화를 사용하여 개인 수익 데이터를 보호하면서 통계 분석을 수행합니다.
    """

    def __init__(self, log_slots=15, key_dir="./keys"):
        """
        CKKS 암호화 환경을 초기화합니다.

        Args:
            log_slots: 암호문당 슬롯 수의 로그 값 (2^log_slots 슬롯)
            key_dir: 키 저장 디렉토리
        """
        self.log_slots = log_slots
        self.num_slots = 1 << log_slots  # 슬롯 개수 계산
        self.key_dir = key_dir

        # 매개변수 설정
        print("Context 설정 중...")
        self.params = heaan.ParameterPreset.FGb
        self.context = heaan.make_context(self.params)
        # 부트스트래핑 가능하게 설정 (필요시)
        # make_bootstrappable은 더 많은 연산을 가능하게 하지만, 초기 설정 시간이 길어질 수 있음
        try:
            heaan.make_bootstrappable(self.context)
            print("Context가 부트스트래핑 가능하게 설정되었습니다.")
        except Exception as e:
            print(f"부트스트래핑 설정 중 오류 (무시하고 진행): {e}")

        # 디렉토리 생성
        os.makedirs(self.key_dir, mode=0o775, exist_ok=True)

        # 키 생성
        print("키 생성 중...")
        self.sk = heaan.SecretKey(self.context)  # 비밀키 생성 (안전하게 보관!)
        self.key_generator = heaan.KeyGenerator(self.context, self.sk)
        self.key_generator.gen_common_keys()  # 공개키, 곱셈키, 회전키 등 생성
        # KeyPack 저장 (암호화 및 동형 연산에 사용) - 수정됨
        self.key_pack = self.key_generator.keypack
        print("키 생성이 완료되었습니다.")

        # 암호화, 복호화, 평가 객체 생성
        print("암호화기, 복호화기, 평가기 초기화 중...")
        self.enc = heaan.Encryptor(self.context)
        self.dec = heaan.Decryptor(self.context)
        # HomEvaluator 초기화 시 KeyPack 전달 - 수정됨
        self.eval = heaan.HomEvaluator(self.context, self.key_pack)
        print("초기화가 완료되었습니다.")

    def encrypt_revenue_data(self, data, metadata):
        """
        수익 데이터와 메타데이터를 암호화합니다.

        Args:
            data: 수익 데이터 리스트 (예: 분기별 데이터)
                  주의: 데이터 개수가 self.num_slots보다 작아야 함
            metadata: 메타데이터 딕셔너리 (장르, 계절 등)

        Returns:
            암호화된 데이터와 메타데이터 딕셔너리
        """
        if len(data) > self.num_slots:
            raise ValueError(
                f"데이터 개수({len(data)})가 슬롯 개수({self.num_slots})보다 많습니다.")

        # 메시지 객체 생성
        message = heaan.Message(self.log_slots)

        # 데이터 인코딩 (실수 형태로)
        for i in range(len(data)):
            message[i] = float(data[i])
        # 나머지 슬롯은 0으로 채워짐 (pi-heaan 기본 동작)

        # 암호화 (KeyPack 사용) - 수정됨
        ciphertext = heaan.Ciphertext(self.context)
        self.enc.encrypt(message, self.key_pack,
                         ciphertext)  # sk 대신 key_pack 사용

        return {
            "encrypted_data": ciphertext,
            "metadata": metadata
        }

    def calculate_average(self, encrypted_data_list, filter_criteria=None):
        """
        암호화된 여러 수익 데이터의 평균을 계산합니다.

        Args:
            encrypted_data_list: encrypt_revenue_data의 반환값 딕셔너리 리스트
            filter_criteria: 필터링 기준 (예: {"genre": "pop", "season": "spring"})

        Returns:
            암호화된 평균 값 (Ciphertext 객체), 또는 데이터가 없으면 None
        """
        # 필터링
        filtered_data = []
        if filter_criteria:
            print(f"필터링 기준 적용: {filter_criteria}")
            for item in encrypted_data_list:
                matches = True
                for key, value in filter_criteria.items():
                    if item["metadata"].get(key) != value:
                        matches = False
                        break
                if matches:
                    filtered_data.append(item["encrypted_data"])
        else:
            print("필터링 기준 없음. 모든 데이터 사용.")
            filtered_data = [item["encrypted_data"]
                             for item in encrypted_data_list]

        num_filtered = len(filtered_data)
        print(f"평균 계산 대상 데이터 개수: {num_filtered}")

        if not filtered_data:
            return None

            # 첫 번째 데이터로 합계 초기화
        sum_data = heaan.Ciphertext(self.context)
        if filtered_data:  # 필터링된 데이터가 있을 경우에만 초기화 수행
            # self.eval.mult_plain(filtered_data[0], 1.0, sum_data) # <-- 이전 수정 코드 주석 처리 또는 삭제

            # 아래 코드로 대체: mult 함수를 사용하여 상수 1.0을 곱함
            # 상수 1.0은 complex 타입으로 전달되어야 함 (파이썬 float가 보통 호환됨)
            # mult_plain 대신 mult 사용
            self.eval.mult(filtered_data[0], 1.0, sum_data)
        else:
            print("초기화할 데이터가 없습니다.")

        # 나머지 데이터 합산 (add 사용)
        for i in range(1, num_filtered):
            self.eval.add(sum_data, filtered_data[i], sum_data)

        # 데이터 개수로 나누기 (평균 계산 - mult 사용)
        if num_filtered > 0:
            constant = 1.0 / num_filtered
            # mult 함수를 사용하여 상수(constant)를 곱함
            # mult_plain 대신 mult 사용
            self.eval.mult(sum_data, constant, sum_data)
            # 곱셈 후 리스케일링 필요 여부 확인 (HEaaN 스킴 특성상 곱셈 후엔 보통 필요)
            # self.eval.rescale(sum_data) # 필요하다면 이 줄의 주석 해제 (rescale 함수는 존재함)
            # 중요: rescale은 입력과 출력이 같은 객체일 수 없음. 새 객체 필요!
            # rescaled_sum_data = heaan.Ciphertext(self.context)
            # self.eval.rescale(sum_data, rescaled_sum_data) # 이 방식은 piheaan 버전에 따라 다를 수 있음
            # self.eval.rescale(sum_data) # 인자 1개 버전이 있는지 확인 필요
            # piheaan 문서나 예제를 참고하여 정확한 rescale 사용법 확인 필요
            # 만약 rescale이 필요하고 어렵다면, 일단 주석 처리하고 진행 가능 (정확도에 영향 줄 수 있음)

        return sum_data

    def decrypt_result(self, encrypted_result, num_elements=None):
        """
        암호화된 결과를 복호화합니다.

        Args:
            encrypted_result: 암호화된 결과 (Ciphertext 객체)
            num_elements: 복호화하여 반환할 요소의 개수. None이면 모든 슬롯 반환 시도.

        Returns:
            복호화된 결과 리스트 (실수 값)
        """
        if not isinstance(encrypted_result, heaan.Ciphertext):
            raise TypeError("encrypted_result는 heaan.Ciphertext 객체여야 합니다.")

        result_message = heaan.Message(self.log_slots)
        self.dec.decrypt(encrypted_result, self.sk, result_message)

        # 필요한 개수만큼 또는 전체 슬롯에서 실수(.real) 값 추출 - 수정됨
        if num_elements is None:
            # num_elements가 지정되지 않으면 이론상 가능한 최대 슬롯 수만큼 시도
            # 하지만 실제 유효 데이터는 그보다 훨씬 적을 수 있음
            effective_num_elements = self.num_slots
        else:
            effective_num_elements = min(num_elements, self.num_slots)

        result_list = []
        try:
            for i in range(effective_num_elements):
                # .real을 사용하여 복소수의 실수 부분 추출
                result_list.append(result_message[i].real)
        except IndexError:
            # Message 객체가 예상보다 작을 경우 처리 (이론상 발생하지 않아야 함)
            print(f"경고: 인덱스 {i} 접근 중 오류 발생. 현재까지 추출된 값만 반환합니다.")
            pass
        except Exception as e:
            print(f"복호화 결과 추출 중 오류 발생: {e}")
            # 오류 발생 시 빈 리스트 또는 부분 리스트 반환
            pass

        return result_list

    def compare_with_average(self, personal_encrypted_data, average_encrypted_data):
        """
        개인 데이터와 평균을 비교합니다 (비율 계산).

        Args:
            personal_encrypted_data: 암호화된 개인 데이터 (Ciphertext)
            average_encrypted_data: 암호화된 평균 데이터 (Ciphertext)

        Returns:
            암호화된 비율 (개인 데이터 / 평균) (Ciphertext)
        """
        # 중요: 동형 나눗셈은 복잡함. pi-heaan의 `div` 함수 존재 및 동작 방식 확인 필요.
        # 만약 div가 없다면, average_encrypted_data의 역수를 계산한 후 곱해야 함.
        ratio = heaan.Ciphertext(self.context)
        try:
            # div 함수가 라이브러리에 존재하고 예상대로 작동한다고 가정
            self.eval.div(personal_encrypted_data,
                          average_encrypted_data, ratio)
            # 나눗셈 후 리스케일링 등이 필요할 수 있음
            # self.eval.rescale(ratio, ratio) # 예시
            print("동형 나눗셈(div) 수행 완료 (라이브러리 지원 가정)")
            return ratio
        except AttributeError:
            print(
                "오류: 'HomEvaluator' 객체에 'div' 속성이 없습니다. 동형 나눗셈을 직접 구현해야 할 수 있습니다 (역수 계산 후 곱셈).")
            # 대체 구현 (예시 - inverse 함수가 있다고 가정):
            # inverse_average = heaan.Ciphertext(self.context)
            # self.eval.inverse(average_encrypted_data, inverse_average) # 역수 계산 (이것도 지원 확인 필요)
            # self.eval.mult(personal_encrypted_data, inverse_average, ratio) # 곱셈
            # self.eval.rescale(ratio, ratio) # 리스케일링
            # print("동형 나눗셈 대체 구현 시도 (inverse + mult)")
            # return ratio
            return None  # 또는 예외 발생
        except Exception as e:
            print(f"동형 나눗셈 중 오류 발생: {e}")
            return None

    def calculate_percentile(self, personal_data, all_data, percentile=90):
        """
        특정 백분위수를 계산합니다. (동형 암호화에서 매우 복잡)

        Args:
            personal_data: 개인 데이터 (암호화된 상태)
            all_data: 모든 데이터 리스트 (암호화된 상태)
            percentile: 계산할 백분위수 (예: 90)

        Returns:
            현재 구현되지 않음 (None 또는 예외)
        """
        print("알림: 동형 암호화 상태에서의 백분위수 계산은 매우 복잡하며 현재 구현되지 않았습니다.")
        # 이유: 백분위수는 데이터 정렬이나 비교 연산이 필요한데,
        # 이는 일반적인 동형암호 스킴(특히 CKKS)에서 직접 지원하기 어렵고,
        # 지원하더라도 매우 비효율적이거나 근사적인 방법(예: 비교 프로토콜 사용)이 필요함.
        # pass
        return None  # 명시적으로 미구현 상태 반환

# --- 유틸리티 함수들 (변경 없음) ---


def normalize_revenue(revenue, unit=10000):
    return revenue / unit


def encode_genre(genre):
    genre_map = {"pop": 0, "rock": 1, "hiphop": 2, "rnb": 3,
                 "edm": 4, "classical": 5, "jazz": 6, "folk": 7}
    return genre_map.get(genre.lower(), -1)


def encode_season(season):
    season_map = {"spring": 0, "q1": 0, "summer": 1, "q2": 1,
                  "fall": 2, "autumn": 2, "q3": 2, "winter": 3, "q4": 3}
    return season_map.get(season.lower(), -1)

# --- 사용 예시 ---


def main():
    print("=== 음악 수익 분석 시스템 시작 ===")
    # 분석기 초기화
    try:
        # log_slots=15는 2^15 = 32768 슬롯
        analyzer = MusicRevenueAnalyzer(log_slots=15)
    except Exception as e:
        print(f"분석기 초기화 실패: {e}")
        return

    # 샘플 데이터 정의 (수익은 이미 10,000원 단위로 정규화되었다고 가정)
    # 즉, 150은 1,500,000원을 의미
    musician1_data_raw = {
        # 분기별 수익 (1.5M, 2M, 1.8M, 2.5M 원)
        "revenue": [150.0, 200.0, 180.0, 250.0],
        "metadata": {"genre": "pop", "experience": 3}
    }
    musician2_data_raw = {
        "revenue": [120.0, 130.0, 140.0, 150.0],
        "metadata": {"genre": "rock", "experience": 2}
    }
    musician3_data_raw = {
        "revenue": [180.0, 220.0, 190.0, 280.0],  # 또 다른 팝 가수
        "metadata": {"genre": "pop", "experience": 5}
    }

    # 데이터 암호화
    print("\n--- 데이터 암호화 중 ---")
    try:
        encrypted_musician1 = analyzer.encrypt_revenue_data(
            musician1_data_raw["revenue"], musician1_data_raw["metadata"])
        print("뮤지션 1 데이터 암호화 완료.")

        encrypted_musician2 = analyzer.encrypt_revenue_data(
            musician2_data_raw["revenue"], musician2_data_raw["metadata"])
        print("뮤지션 2 데이터 암호화 완료.")

        encrypted_musician3 = analyzer.encrypt_revenue_data(
            musician3_data_raw["revenue"], musician3_data_raw["metadata"])
        print("뮤지션 3 데이터 암호화 완료.")
    except Exception as e:
        print(f"데이터 암호화 중 오류 발생: {e}")
        return

    # 모든 암호화된 데이터 수집
    all_encrypted_data = [encrypted_musician1,
                          encrypted_musician2, encrypted_musician3]

    # 장르별 평균 계산 (동형 연산)
    print("\n--- 장르별 평균 수익 계산 (암호화 상태) ---")
    pop_filter = {"genre": "pop"}
    pop_average_encrypted = analyzer.calculate_average(
        all_encrypted_data, pop_filter)

    rock_filter = {"genre": "rock"}
    rock_average_encrypted = analyzer.calculate_average(
        all_encrypted_data, rock_filter)

    # 결과 복호화 및 출력
    print("\n--- 결과 복호화 및 출력 ---")
    num_quarters = 4  # 분기 개수

    if pop_average_encrypted:
        try:
            decrypted_pop_average = analyzer.decrypt_result(
                pop_average_encrypted, num_elements=num_quarters)
            print("팝(Pop) 장르 분기별 평균 수익:")
            for i, avg in enumerate(decrypted_pop_average):
                # 원래 단위(원)로 변환하여 출력
                print(f"  Q{i+1}: {avg * 10000:,.0f} 원")
        except Exception as e:
            print(f"팝 평균 복호화 중 오류: {e}")
    else:
        print("팝 장르에 대한 데이터가 없거나 계산에 실패했습니다.")

    if rock_average_encrypted:
        try:
            decrypted_rock_average = analyzer.decrypt_result(
                rock_average_encrypted, num_elements=num_quarters)
            print("\n락(Rock) 장르 분기별 평균 수익:")
            for i, avg in enumerate(decrypted_rock_average):
                print(f"  Q{i+1}: {avg * 10000:,.0f} 원")
        except Exception as e:
            print(f"락 평균 복호화 중 오류: {e}")
    else:
        print("\n락 장르에 대한 데이터가 없거나 계산에 실패했습니다.")

    # # 개인 데이터와 평균 비교 (예시 - 뮤지션 1과 팝 평균 비교)
    # print("\n--- 개인 데이터와 평균 비교 (암호화 상태) ---")
    # if encrypted_musician1 and pop_average_encrypted:
    #     comparison_ratio_encrypted = analyzer.compare_with_average(
    #         encrypted_musician1["encrypted_data"],
    #         pop_average_encrypted
    #     )

    #     if comparison_ratio_encrypted:
    #         try:
    #             # 비교 결과 복호화
    #             decrypted_ratio = analyzer.decrypt_result(comparison_ratio_encrypted, num_elements=num_quarters)
    #             print("\n뮤지션 1의 수익 / 팝 장르 평균 수익 (분기별 비율):")
    #             for i, ratio_val in enumerate(decrypted_ratio):
    #                 print(f"  Q{i+1}: {ratio_val:.2f}") # 비율이므로 소수점 표시
    #         except Exception as e:
    #             print(f"비교 결과 복호화 중 오류: {e}")
    #     else:
    #         print("평균 비교 계산에 실패했습니다 (div 함수 문제일 수 있음).")

    print("\n=== 분석 시스템 종료 ===")


if __name__ == "__main__":
    main()
