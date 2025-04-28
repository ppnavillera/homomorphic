import piheaan as heaan
import numpy as np
import os
from typing import List, Dict, Tuple, Any, Optional


class HomomorphicStats:
    """
    동형 암호화 상태에서 통계 연산을 수행하는 클래스
    """

    def __init__(self, context=None, log_slots=15, key_dir="./keys"):
        """
        CKKS 암호화 환경을 초기화합니다.

        Args:
            context: 기존 CKKS 컨텍스트 (없으면 새로 생성)
            log_slots: 암호문당 슬롯 수의 로그 값
            key_dir: 키 저장 디렉토리
        """
        self.log_slots = log_slots
        self.key_dir = key_dir

        # 컨텍스트 생성 또는 기존 것 사용
        if context is None:
            self.params = heaan.ParameterPreset.FGb  # 128비트 보안 수준의 파라미터
            self.context = heaan.make_context(self.params)
            heaan.make_bootstrappable(self.context)
        else:
            self.context = context

        # 디렉토리 생성
        os.makedirs(self.key_dir, mode=0o775, exist_ok=True)

        # 키 생성
        self.sk = heaan.SecretKey(self.context)
        self.key_generator = heaan.KeyGenerator(self.context, self.sk)
        self.key_generator.gen_common_keys()

        # 암호화, 복호화, 평가 객체 생성
        self.pk = heaan.PublicKey(self.context)
        self.enc = heaan.Encryptor(self.context)
        self.dec = heaan.Decryptor(self.context)
        self.eval = heaan.HomEvaluator(self.context)

        # 부트스트랩핑 키 생성 (긴 연산 체인을 위함)
        self.key_generator.gen_bootstrap_keys()

    def encrypt_vector(self, data: List[float]) -> heaan.Ciphertext:
        """
        벡터 데이터를 암호화합니다.

        Args:
            data: 암호화할 실수값 리스트

        Returns:
            암호화된 벡터 데이터
        """
        # 메시지 객체 생성
        message = heaan.Message(self.log_slots)

        # 데이터 인코딩
        for i in range(min(len(data), 2**self.log_slots)):
            message[i] = float(data[i])

        # 암호화
        ciphertext = heaan.Ciphertext(self.context)
        self.enc.encrypt(message, self.pk, ciphertext)

        return ciphertext

    def decrypt_vector(self, ciphertext: heaan.Ciphertext, length: int = None) -> List[float]:
        """
        암호화된 벡터를 복호화합니다.

        Args:
            ciphertext: 복호화할 암호문
            length: 반환할 벡터의 길이 (기본값: 모든 데이터)

        Returns:
            복호화된 실수값 리스트
        """
        result_message = heaan.Message(self.log_slots)
        self.dec.decrypt(ciphertext, self.sk, result_message)

        # 기본 길이는 모든 슬롯
        if length is None:
            length = 2**self.log_slots

        # 메시지를 Python 리스트로 변환
        result_list = [float(result_message[i])
                       for i in range(min(length, 2**self.log_slots))]

        return result_list

    def compute_sum(self, encrypted_vectors: List[heaan.Ciphertext]) -> heaan.Ciphertext:
        """
        암호화된 여러 벡터의 합을 계산합니다.

        Args:
            encrypted_vectors: 암호화된 벡터 리스트

        Returns:
            암호화된 합계 벡터
        """
        if not encrypted_vectors:
            raise ValueError("벡터 리스트가 비어 있습니다.")

        # 첫 번째 벡터로 합계 초기화
        sum_vector = heaan.Ciphertext(self.context)
        self.eval.copy(encrypted_vectors[0], sum_vector)

        # 나머지 벡터 합산
        for i in range(1, len(encrypted_vectors)):
            self.eval.add(sum_vector, encrypted_vectors[i], sum_vector)

            # 노이즈 관리: 필요시 부트스트랩핑 수행
            if (i + 1) % 10 == 0:  # 예: 10개마다 부트스트랩핑
                self.eval.bootstrap(sum_vector, sum_vector)
                return sum_vector

    def compute_average(self, encrypted_vectors: List[heaan.Ciphertext]) -> heaan.Ciphertext:
        """
        암호화된 여러 벡터의 평균을 계산합니다.

        Args:
            encrypted_vectors: 암호화된 벡터 리스트

        Returns:
            암호화된 평균 벡터
        """
        # 합계 계산
        sum_vector = self.compute_sum(encrypted_vectors)

        # 배열 크기로 나누기
        avg_vector = heaan.Ciphertext(self.context)
        scalar = 1.0 / len(encrypted_vectors)
        self.eval.mult_plain(sum_vector, scalar, avg_vector)

        return avg_vector

    def compute_percentile_approximation(self, encrypted_vectors: List[heaan.Ciphertext],
                                         percentile: float,
                                         min_val: float,
                                         max_val: float,
                                         num_buckets: int = 20) -> heaan.Ciphertext:
        """
        암호화된 데이터의 백분위수를 근사적으로 계산합니다.

        동형 암호화에서 정확한 백분위수 계산은 어렵기 때문에 버킷 기반 근사 방법을 사용합니다.

        Args:
            encrypted_vectors: 암호화된 벡터 리스트
            percentile: 계산할 백분위수 (0~100)
            min_val: 예상되는 최소값
            max_val: 예상되는 최대값
            num_buckets: 버킷 수 (정밀도와 관련)

        Returns:
            암호화된 백분위수 근사값
        """
        # 범위를 균등한 버킷으로 나누기
        bucket_size = (max_val - min_val) / num_buckets
        buckets = [min_val + i * bucket_size for i in range(num_buckets + 1)]

        # 계수 함수 생성 (다항식 근사)
        # 백분위수 계산을 위한 복잡한 로직은 이 예제에서 간소화됨
        # 실제 구현에서는 더 정교한 근사 방법이 필요할 수 있음

        # 각 벡터에 대한 버킷 카운트를 계산하는 함수
        # 이 부분은 실제 CKKS에서는 복잡하며, 다항식 근사나 복잡한 동형 연산이 필요함
        # 여기서는 개념만 제시함

        # 예상 구현:
        # 1. 각 버킷의 상한값보다 작거나 같은 값의 개수를 동형 연산으로 계산
        # 2. 이 카운트를 기반으로 해당 백분위수가 속하는 버킷을 결정
        # 3. 버킷 내에서 선형 보간으로 최종 값 추정

        # 간소화된 예제 구현:
        # 이 예제는 개념을 설명하기 위한 것으로, 실제로는 더 복잡한 구현이 필요함
        result = heaan.Ciphertext(self.context)

        # 결과로 중간 버킷값 반환 (실제 백분위수가 아님, 예시 용도)
        target_bucket_index = int(percentile / 100 * num_buckets)
        target_value = buckets[target_bucket_index]

        # 결과 암호화 (실제로는 동형 연산으로 계산해야 함)
        dummy_msg = heaan.Message(self.log_slots)
        dummy_msg[0] = target_value
        self.enc.encrypt(dummy_msg, self.pk, result)

        return result

    def compare_encrypted(self, encrypted_a: heaan.Ciphertext,
                          encrypted_b: heaan.Ciphertext) -> heaan.Ciphertext:
        """
        두 암호화된 벡터의 비율(a/b)을 계산합니다.

        Args:
            encrypted_a: 암호화된 벡터 A
            encrypted_b: 암호화된 벡터 B

        Returns:
            암호화된 결과 벡터 (A/B)
        """
        result = heaan.Ciphertext(self.context)

        # CKKS에서는 나눗셈을 직접 지원하지 않기 때문에
        # B의 역수에 대한 근사 다항식을 계산하고 이를 A와 곱하는 방식을 사용함
        # 실제 구현은 복잡하지만, 여기서는 내장 함수를 사용
        self.eval.div(encrypted_a, encrypted_b, result)

        return result

    def filter_by_range(self, encrypted_vector: heaan.Ciphertext,
                        lower_bound: float,
                        upper_bound: float) -> heaan.Ciphertext:
        """
        암호화된 벡터에서 특정 범위 내의 값을 필터링합니다.

        Args:
            encrypted_vector: 암호화된 벡터
            lower_bound: 하한값
            upper_bound: 상한값

        Returns:
            암호화된 마스크 벡터 (범위 내 1, 범위 외 0)
        """
        # 이 함수는 CKKS에서 구현하기 복잡함
        # 다항식 근사를 사용하여 조건부 로직을 구현해야 함

        # 간소화된 예제:
        # 실제로는 범위 검사를 위한 다항식 함수 근사가 필요함
        result = heaan.Ciphertext(self.context)

        # 이 부분은 실제 구현에서는 다항식 근사로 대체되어야 함
        # 예를 들어, sigmoid 함수의 다항식 근사를 사용하여 범위 검사를 구현할 수 있음

        # 간소화된 구현:
        # 이 로직은 개념적인 설명이며, 실제로는 암호화된 상태에서 동형 연산으로 구현되어야 함
        dummy_msg = heaan.Message(self.log_slots)
        for i in range(2**self.log_slots):
            dummy_msg[i] = 1.0  # 모든 값을 1로 설정 (실제로는 조건에 따라 0 또는 1이어야 함)

        self.enc.encrypt(dummy_msg, self.pk, result)

        return result

    def apply_differential_privacy(self, encrypted_vector: heaan.Ciphertext,
                                   epsilon: float = 0.1) -> heaan.Ciphertext:
        """
        암호화된 벡터에 차등 프라이버시를 적용합니다.

        Args:
            encrypted_vector: 암호화된 벡터
            epsilon: 프라이버시 파라미터 (작을수록 더 강한 보호)

        Returns:
            노이즈가 추가된 암호화 벡터
        """
        # 라플라스 노이즈 생성 (실제로는 클라이언트에서 생성하여 암호화해야 함)
        # 차등 프라이버시를 위한 노이즈 스케일 계산
        noise_scale = 1.0 / epsilon

        # 노이즈 벡터 생성 및 암호화
        noise_msg = heaan.Message(self.log_slots)
        for i in range(2**self.log_slots):
            # 라플라스 분포에서 노이즈 샘플링
            # 여기서는 간단히 평균 0의 작은 노이즈로 시뮬레이션
            noise = np.random.laplace(0, noise_scale)
            noise_msg[i] = noise

        noise_cipher = heaan.Ciphertext(self.context)
        self.enc.encrypt(noise_msg, self.pk, noise_cipher)

        # 원본 데이터에 노이즈 추가
        result = heaan.Ciphertext(self.context)
        self.eval.add(encrypted_vector, noise_cipher, result)

        return result


# 예제 사용법
def example_usage():
    """
    HomomorphicStats 클래스 사용 예제
    """
    # 동형 통계 객체 초기화
    hom_stats = HomomorphicStats(log_slots=10)  # 더 작은 슬롯 크기 사용

    # 샘플 데이터 (음악가 수익 데이터)
    musician_data = [
        [150, 200, 180, 250],  # 첫 번째 음악가의 분기별 수익 (만원)
        [120, 130, 140, 150],  # 두 번째 음악가
        [200, 220, 210, 230],  # 세 번째 음악가
        [80, 90, 100, 110]     # 네 번째 음악가
    ]

    # 데이터 암호화
    encrypted_data = []
    for data in musician_data:
        encrypted_data.append(hom_stats.encrypt_vector(data))

    print("데이터 암호화 완료")

    # 평균 계산
    encrypted_avg = hom_stats.compute_average(encrypted_data)

    # 결과 복호화
    decrypted_avg = hom_stats.decrypt_vector(encrypted_avg, length=4)
    print(f"분기별 평균 수익: {decrypted_avg}")

    # 첫 번째 음악가와 평균 비교
    encrypted_ratio = hom_stats.compare_encrypted(
        encrypted_data[0], encrypted_avg)
    decrypted_ratio = hom_stats.decrypt_vector(encrypted_ratio, length=4)
    print(f"첫 번째 음악가의 평균 대비 비율: {decrypted_ratio}")

    # 차등 프라이버시 적용
    encrypted_private_avg = hom_stats.apply_differential_privacy(
        encrypted_avg, epsilon=0.5)
    decrypted_private_avg = hom_stats.decrypt_vector(
        encrypted_private_avg, length=4)
    print(f"차등 프라이버시 적용 후 평균: {decrypted_private_avg}")


if __name__ == "__main__":
    example_usage()


class HomomorphicStats:
    """
    동형 암호화 상태에서 통계 연산을 수행하는 클래스
    """

    def __init__(self, context=None, log_slots=15, key_dir="./keys"):
        """
        CKKS 암호화 환경을 초기화합니다.

        Args:
            context: 기존 CKKS 컨텍스트 (없으면 새로 생성)
            log_slots: 암호문당 슬롯 수의 로그 값
            key_dir: 키 저장 디렉토리
        """
        self.log_slots = log_slots
        self.key_dir = key_dir

        # 컨텍스트 생성 또는 기존 것 사용
        if context is None:
            self.params = heaan.ParameterPreset.FGb  # 128비트 보안 수준의 파라미터
            self.context = heaan.make_context(self.params)
            heaan.make_bootstrappable(self.context)
        else:
            self.context = context

        # 디렉토리 생성
        os.makedirs(self.key_dir, mode=0o775, exist_ok=True)

        # 키 생성
        self.sk = heaan.SecretKey(self.context)
        self.key_generator = heaan.KeyGenerator(self.context, self.sk)
        self.key_generator.gen_common_keys()

        # 암호화, 복호화, 평가 객체 생성
        self.pk = heaan.PublicKey(self.context)
        self.enc = heaan.Encryptor(self.context)
        self.dec = heaan.Decryptor(self.context)
        self.eval = heaan.HomEvaluator(self.context)

        # 부트스트랩핑 키 생성 (긴 연산 체인을 위함)
        self.key_generator.gen_bootstrap_keys()

    def encrypt_vector(self, data: List[float]) -> heaan.Ciphertext:
        """
        벡터 데이터를 암호화합니다.

        Args:
            data: 암호화할 실수값 리스트

        Returns:
            암호화된 벡터 데이터
        """
        # 메시지 객체 생성
        message = heaan.Message(self.log_slots)

        # 데이터 인코딩
        for i in range(min(len(data), 2**self.log_slots)):
            message[i] = float(data[i])

        # 암호화
        ciphertext = heaan.Ciphertext(self.context)
        self.enc.encrypt(message, self.pk, ciphertext)

        return ciphertext

    def decrypt_vector(self, ciphertext: heaan.Ciphertext, length: int = None) -> List[float]:
        """
        암호화된 벡터를 복호화합니다.

        Args:
            ciphertext: 복호화할 암호문
            length: 반환할 벡터의 길이 (기본값: 모든 데이터)

        Returns:
            복호화된 실수값 리스트
        """
        result_message = heaan.Message(self.log_slots)
        self.dec.decrypt(ciphertext, self.sk, result_message)

        # 기본 길이는 모든 슬롯
        if length is None:
            length = 2**self.log_slots

        # 메시지를 Python 리스트로 변환
        result_list = [float(result_message[i])
                       for i in range(min(length, 2**self.log_slots))]

        return result_list

    def compute_sum(self, encrypted_vectors: List[heaan.Ciphertext]) -> heaan.Ciphertext:
        """
        암호화된 여러 벡터의 합을 계산합니다.

        Args:
            encrypted_vectors: 암호화된 벡터 리스트

        Returns:
            암호화된 합계 벡터
        """
        if not encrypted_vectors:
            raise ValueError("벡터 리스트가 비어 있습니다.")

        # 첫 번째 벡터로 합계 초기화
        sum_vector = heaan.Ciphertext(self.context)
        self.eval.copy(encrypted_vectors[0], sum_vector)

        # 나머지 벡터 합산
        for i in range(1, len(encrypted_vectors)):
            self.eval.add(sum_vector, encrypted_vectors[i], sum_vector)

            # 노이즈 관리: 필요시 부트스트랩핑 수행
            if (i + 1) % 10 == 0:  # 예: 10개마다 부트스트랩핑
                self.eval.bootstrap(sum_vector, sum_vector)
