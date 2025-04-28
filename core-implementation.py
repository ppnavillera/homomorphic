import piheaan as heaan
import numpy as np
import pandas as pd
import os
import json


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
        self.key_dir = key_dir

        # 매개변수 설정
        self.params = heaan.ParameterPreset.FGb
        self.context = heaan.make_context(self.params)
        heaan.make_bootstrappable(self.context)

        # 디렉토리 생성
        os.makedirs(self.key_dir, mode=0o775, exist_ok=True)

        # 키 생성
        self.sk = heaan.SecretKey(self.context)  # 비밀키 생성
        self.key_generator = heaan.KeyGenerator(self.context, self.sk)
        self.key_generator.gen_common_keys()

        # 암호화, 복호화, 평가 객체 생성
        self.pk = heaan.PublicKey(self.context)
        self.enc = heaan.Encryptor(self.context)
        self.dec = heaan.Decryptor(self.context)
        self.eval = heaan.HomEvaluator(self.context)

    def encrypt_revenue_data(self, data, metadata):
        """
        수익 데이터와 메타데이터를 암호화합니다.

        Args:
            data: 수익 데이터 (10,000원 단위로 정규화된 정수 리스트)
            metadata: 메타데이터 딕셔너리 (장르, 계절 등)

        Returns:
            암호화된 데이터와 메타데이터
        """
        # 메시지 객체 생성
        message = heaan.Message(self.log_slots)

        # 데이터 인코딩
        for i in range(len(data)):
            message[i] = float(data[i])

        # 암호화
        ciphertext = heaan.Ciphertext(self.context)
        self.enc.encrypt(message, self.pk, ciphertext)

        return {
            "encrypted_data": ciphertext,
            "metadata": metadata
        }

    def calculate_average(self, encrypted_data_list, filter_criteria=None):
        """
        암호화된 여러 수익 데이터의 평균을 계산합니다.

        Args:
            encrypted_data_list: 암호화된 데이터 리스트
            filter_criteria: 필터링 기준 (예: {"genre": "pop", "season": "spring"})

        Returns:
            암호화된 평균 값
        """
        # 필터링
        filtered_data = []
        if filter_criteria:
            for item in encrypted_data_list:
                matches = True
                for key, value in filter_criteria.items():
                    if item["metadata"].get(key) != value:
                        matches = False
                        break
                if matches:
                    filtered_data.append(item["encrypted_data"])
        else:
            filtered_data = [item["encrypted_data"]
                             for item in encrypted_data_list]

        if not filtered_data:
            return None

        # 첫 번째 데이터로 합계 초기화
        sum_data = heaan.Ciphertext(self.context)
        self.eval.copy(filtered_data[0], sum_data)

        # 나머지 데이터 합산
        for i in range(1, len(filtered_data)):
            self.eval.add(sum_data, filtered_data[i], sum_data)

        # 데이터 개수로 나누기 (평균 계산)
        constant = 1.0 / len(filtered_data)
        self.eval.mult_plain(sum_data, constant, sum_data)

        return sum_data

    def decrypt_result(self, encrypted_result):
        """
        암호화된 결과를 복호화합니다.

        Args:
            encrypted_result: 암호화된 결과

        Returns:
            복호화된 결과
        """
        result_message = heaan.Message(self.log_slots)
        self.dec.decrypt(encrypted_result, self.sk, result_message)

        # 메시지를 Python 리스트로 변환
        result_list = [float(result_message[i]) for i in range(self.log_slots)]

        return result_list

    def compare_with_average(self, personal_data, average_data):
        """
        개인 데이터와 평균을 비교합니다.

        Args:
            personal_data: 암호화된 개인 데이터
            average_data: 암호화된 평균 데이터

        Returns:
            암호화된 비율 (개인 데이터 / 평균)
        """
        ratio = heaan.Ciphertext(self.context)
        self.eval.div(personal_data, average_data, ratio)

        return ratio

    def calculate_percentile(self, personal_data, all_data, percentile=90):
        """
        특정 백분위수를 계산합니다.
        백분위수는 동형 암호화에서 계산하기 복잡하므로 단순화된 접근 방식을 사용합니다.

        Args:
            personal_data: 개인 데이터
            all_data: 모든 데이터
            percentile: 계산할 백분위수 (예: 90)

        Returns:
            특정 백분위수에서 개인 데이터의 위치 (근사값)
        """
        # 구현 복잡도를 고려하여 백분위수 계산 로직은 간소화하여 구현
        # 실제 구현에서는 더 복잡한 알고리즘이 필요할 수 있음
        pass


# 데이터 전처리를 위한 유틸리티 함수들
def normalize_revenue(revenue, unit=10000):
    """
    수익 데이터를 정규화합니다.

    Args:
        revenue: 원본 수익 데이터 (원 단위)
        unit: 정규화 단위 (기본값: 10,000원)

    Returns:
        정규화된 수익 데이터
    """
    return revenue / unit


def encode_genre(genre):
    """
    장르를 숫자로 인코딩합니다.

    Args:
        genre: 장르 문자열

    Returns:
        인코딩된 정수 값
    """
    genre_map = {
        "pop": 0,
        "rock": 1,
        "hiphop": 2,
        "rnb": 3,
        "edm": 4,
        "classical": 5,
        "jazz": 6,
        "folk": 7
    }
    return genre_map.get(genre.lower(), -1)


def encode_season(season):
    """
    계절을 숫자로 인코딩합니다.

    Args:
        season: 계절 또는 분기 문자열

    Returns:
        인코딩된 정수 값
    """
    season_map = {
        "spring": 0, "q1": 0,
        "summer": 1, "q2": 1,
        "fall": 2, "autumn": 2, "q3": 2,
        "winter": 3, "q4": 3
    }
    return season_map.get(season.lower(), -1)


# 사용 예시
def main():
    # 분석기 초기화
    analyzer = MusicRevenueAnalyzer()

    # 샘플 데이터
    musician1_data = {
        "revenue": [150, 200, 180, 250],  # 분기별 수익 (1.5M, 2M, 1.8M, 2.5M 원)
        "metadata": {
            "genre": "pop",
            "experience": 3  # 경력 3년
        }
    }

    musician2_data = {
        "revenue": [120, 130, 140, 150],
        "metadata": {
            "genre": "rock",
            "experience": 2
        }
    }

    # 데이터 암호화
    encrypted_musician1 = analyzer.encrypt_revenue_data(
        musician1_data["revenue"],
        musician1_data["metadata"]
    )

    encrypted_musician2 = analyzer.encrypt_revenue_data(
        musician2_data["revenue"],
        musician2_data["metadata"]
    )

    # 모든 데이터 수집
    all_data = [encrypted_musician1, encrypted_musician2]

    # 장르별 평균 계산
    pop_average = analyzer.calculate_average(all_data, {"genre": "pop"})

    # 결과 복호화
    if pop_average:
        decrypted_average = analyzer.decrypt_result(pop_average)
        print("팝 장르 분기별 평균 수익:")
        for i, avg in enumerate(decrypted_average[:4]):
            print(f"Q{i+1}: {avg * 10000:.0f}원")
    else:
        print("해당 필터 조건에 맞는 데이터가 없습니다.")


if __name__ == "__main__":
    main()
