import numpy as np
from typing import Dict, List, Tuple, Any, Optional
import json
import os


class RevenueDataEncoder:
    """
    음악 수익 데이터를 동형 암호화를 위해 적절히 인코딩하는 클래스
    """

    def __init__(self, revenue_unit: int = 10000, max_quarters: int = 4):
        """
        데이터 인코더를 초기화합니다.

        Args:
            revenue_unit: 수익 정규화 단위 (기본값: 10,000원)
            max_quarters: 최대 분기 수 (기본값: 4)
        """
        self.revenue_unit = revenue_unit
        self.max_quarters = max_quarters

        # 장르 및 계절 인코딩 매핑
        self.genre_mapping = {
            "pop": 0,
            "rock": 1,
            "hiphop": 2,
            "rnb": 3,
            "edm": 4,
            "classical": 5,
            "jazz": 6,
            "folk": 7,
            "other": 8
        }

        self.season_mapping = {
            "spring": 0,
            "q1": 0,
            "summer": 1,
            "q2": 1,
            "fall": 2,
            "autumn": 2,
            "q3": 2,
            "winter": 3,
            "q4": 3
        }

        self.experience_bins = [
            (0, 2),    # 신인 (0-2년)
            (3, 5),    # 초중견 (3-5년)
            (6, 10),   # 중견 (6-10년)
            (11, 20),  # 베테랑 (11-20년)
            (21, 100)  # 원로 (21년 이상)
        ]

    def normalize_revenue(self, revenue: List[float]) -> List[float]:
        """
        수익 데이터를 정규화합니다.

        Args:
            revenue: 원본 수익 데이터 (원 단위)

        Returns:
            정규화된 수익 데이터
        """
        return [r / self.revenue_unit for r in revenue]

    def denormalize_revenue(self, normalized_revenue: List[float]) -> List[float]:
        """
        정규화된 수익 데이터를 원래 단위로 되돌립니다.

        Args:
            normalized_revenue: 정규화된 수익 데이터

        Returns:
            원래 단위의 수익 데이터
        """
        return [r * self.revenue_unit for r in normalized_revenue]

    def encode_genre(self, genre: str) -> int:
        """
        장르를 숫자로 인코딩합니다.

        Args:
            genre: 장르 문자열

        Returns:
            인코딩된 정수 값
        """
        return self.genre_mapping.get(genre.lower(), self.genre_mapping["other"])

    def decode_genre(self, code: int) -> str:
        """
        인코딩된 장르 코드를 문자열로 디코딩합니다.

        Args:
            code: 인코딩된 장르 코드

        Returns:
            장르 문자열
        """
        for genre, genre_code in self.genre_mapping.items():
            if genre_code == code:
                return genre
        return "unknown"

    def encode_season(self, season: str) -> int:
        """
        계절/분기를 숫자로 인코딩합니다.

        Args:
            season: 계절 또는 분기 문자열

        Returns:
            인코딩된 정수 값
        """
        return self.season_mapping.get(season.lower(), -1)

    def decode_season(self, code: int) -> str:
        """
        인코딩된 계절/분기 코드를 문자열로 디코딩합니다.

        Args:
            code: 인코딩된 계절/분기 코드

        Returns:
            계절/분기 문자열
        """
        seasons = ["Q1 (봄)", "Q2 (여름)", "Q3 (가을)", "Q4 (겨울)"]
        if 0 <= code < len(seasons):
            return seasons[code]
        return "unknown"

    def encode_experience(self, years: int) -> int:
        """
        경력 연수를 범주형 빈으로 인코딩합니다.

        Args:
            years: 경력 연수

        Returns:
            인코딩된 경력 범주 (0-4)
        """
        for i, (min_years, max_years) in enumerate(self.experience_bins):
            if min_years <= years <= max_years:
                return i
        return 4  # 기본값: 원로

    def decode_experience(self, code: int) -> str:
        """
        인코딩된 경력 코드를 문자열로 디코딩합니다.

        Args:
            code: 인코딩된 경력 코드

        Returns:
            경력 범주 문자열
        """
        experience_labels = ["신인 (0-2년)", "초중견 (3-5년)",
                             "중견 (6-10년)", "베테랑 (11-20년)", "원로 (21년+)"]
        if 0 <= code < len(experience_labels):
            return experience_labels[code]
        return "unknown"

    def encode_revenue_data(self, raw_data: Dict[str, Any]) -> Tuple[List[float], Dict[str, int]]:
        """
        원시 수익 데이터와 메타데이터를 인코딩합니다.

        Args:
            raw_data: 원시 데이터 딕셔너리
                {
                    "revenue": [q1, q2, q3, q4],
                    "genre": "장르",
                    "experience": 경력연수,
                    "region": "지역" (옵션)
                }

        Returns:
            (인코딩된 수익 데이터, 인코딩된 메타데이터) 튜플
        """
        # 수익 데이터 정규화
        normalized_revenue = self.normalize_revenue(raw_data["revenue"])

        # 분기별 수익 패딩 (필요시)
        padded_revenue = normalized_revenue.copy()
        if len(padded_revenue) < self.max_quarters:
            padded_revenue.extend(
                [0.0] * (self.max_quarters - len(padded_revenue)))

        # 메타데이터 인코딩
        encoded_metadata = {
            "genre": self.encode_genre(raw_data.get("genre", "other")),
            "experience": self.encode_experience(raw_data.get("experience", 0))
        }

        # 지역 정보가 있는 경우 추가 (지역 매핑은 간소화)
        if "region" in raw_data:
            # 여기서는 간단하게 처리 (실제로는 더 복잡한 매핑 필요)
            region_mapping = {"seoul": 0, "busan": 1, "other": 2}
            encoded_metadata["region"] = region_mapping.get(
                raw_data["region"].lower(), 2)

        return padded_revenue, encoded_metadata

    def prepare_data_for_encryption(self, revenue_data: List[float], metadata: Dict[str, int]) -> List[float]:
        """
        암호화를 위해 데이터를 준비합니다.
        수익 데이터와 메타데이터를 단일 벡터로 결합합니다.

        Args:
            revenue_data: 정규화된 수익 데이터
            metadata: 인코딩된 메타데이터

        Returns:
            암호화를 위한 결합된 벡터
        """
        # 결합된 벡터 형식:
        # [q1, q2, q3, q4, genre, experience, region(optional), 0, 0, ...]
        combined_vector = revenue_data.copy()

        # 메타데이터 추가
        combined_vector.append(float(metadata.get("genre", 0)))
        combined_vector.append(float(metadata.get("experience", 0)))
        if "region" in metadata:
            combined_vector.append(float(metadata["region"]))

        return combined_vector

    def extract_data_from_decrypted(self, decrypted_vector: List[float]) -> Tuple[List[float], Dict[str, Any]]:
        """
        복호화된 벡터에서 수익 데이터와 메타데이터를 추출합니다.

        Args:
            decrypted_vector: 복호화된 벡터

        Returns:
            (수익 데이터, 메타데이터) 튜플
        """
        # 수익 데이터 추출 (처음 max_quarters 값)
        revenue_data = decrypted_vector[:self.max_quarters]

        # 메타데이터 추출
        metadata_index = self.max_quarters
        metadata = {}

        # 각 메타데이터 필드 추출 및 디코딩
        if len(decrypted_vector) > metadata_index:
            genre_code = int(round(decrypted_vector[metadata_index]))
            metadata["genre"] = self.decode_genre(genre_code)
            metadata_index += 1

        if len(decrypted_vector) > metadata_index:
            experience_code = int(round(decrypted_vector[metadata_index]))
            metadata["experience"] = self.decode_experience(experience_code)
            metadata_index += 1

        if len(decrypted_vector) > metadata_index:
            region_code = int(round(decrypted_vector[metadata_index]))
            # 지역 디코딩 (간소화됨)
            regions = ["서울", "부산", "기타"]
            if 0 <= region_code < len(regions):
                metadata["region"] = regions[region_code]

        # 수익 데이터 원래 단위로 변환
        denormalized_revenue = self.denormalize_revenue(revenue_data)

        return denormalized_revenue, metadata

    def save_encoded_data(self, data: List[Tuple[List[float], Dict[str, int]]], filename: str) -> None:
        """
        인코딩된 데이터를 파일에 저장합니다.

        Args:
            data: 인코딩된 데이터 리스트 [(수익 데이터, 메타데이터), ...]
            filename: 저장할 파일 경로
        """
        serializable_data = []
        for revenue, metadata in data:
            serializable_data.append({
                "revenue": revenue,
                "metadata": metadata
            })

        with open(filename, 'w') as f:
            json.dump(serializable_data, f)

    def load_encoded_data(self, filename: str) -> List[Tuple[List[float], Dict[str, int]]]:
        """
        인코딩된 데이터를 파일에서 로드합니다.

        Args:
            filename: 로드할 파일 경로

        Returns:
            인코딩된 데이터 리스트 [(수익 데이터, 메타데이터), ...]
        """
        with open(filename, 'r') as f:
            serialized_data = json.load(f)

        data = []
        for item in serialized_data:
            data.append((item["revenue"], item["metadata"]))

        return data


# 데이터 증강 및 테스트 데이터 생성 클래스
class TestDataGenerator:
    """
    테스트용 가상 음악 창작자 데이터를 생성하는 클래스
    """

    def __init__(self, encoder: RevenueDataEncoder, num_creators: int = 20, seed: int = 42):
        """
        테스트 데이터 생성기를 초기화합니다.

        Args:
            encoder: 데이터 인코더 인스턴스
            num_creators: 생성할 창작자 수
            seed: 랜덤 시드
        """
        self.encoder = encoder
        self.num_creators = num_creators
        np.random.seed(seed)

        # 장르별 평균 수익 (만원 단위)
        self.genre_avg_revenue = {
            "pop": 180,
            "rock": 150,
            "hiphop": 200,
            "rnb": 170,
            "edm": 220,
            "classical": 130,
            "jazz": 140,
            "folk": 120
        }

        # 경력별 수익 배수
        self.experience_multiplier = {
            0: 0.7,   # 신인 (0-2년)
            1: 0.9,   # 초중견 (3-5년)
            2: 1.0,   # 중견 (6-10년)
            3: 1.2,   # 베테랑 (11-20년)
            4: 1.3    # 원로 (21년+)
        }

        # 계절별 수익 배수
        self.seasonal_multiplier = {
            0: 0.9,   # Q1 (봄)
            1: 1.0,   # Q2 (여름)
            2: 1.1,   # Q3 (가을)
            3: 1.2    # Q4 (겨울)
        }

    def generate_random_creator(self) -> Dict[str, Any]:
        """
        랜덤한 창작자 데이터를 생성합니다.

        Returns:
            창작자 데이터 딕셔너리
        """
        # 랜덤 장르 선택
        genres = list(self.genre_avg_revenue.keys())
        genre = np.random.choice(genres)

        # 랜덤 경력 선택
        experience_code = np.random.randint(0, 5)  # 0-4
        if experience_code == 0:  # 신인
            experience_years = np.random.randint(0, 3)
        elif experience_code == 1:  # 초중견
            experience_years = np.random.randint(3, 6)
        elif experience_code == 2:  # 중견
            experience_years = np.random.randint(6, 11)
        elif experience_code == 3:  # 베테랑
            experience_years = np.random.randint(11, 21)
        else:  # 원로
            experience_years = np.random.randint(21, 40)

        # 기본 수익 계산 (장르 평균 * 경력 배수)
        base_revenue = self.genre_avg_revenue[genre] * \
            self.experience_multiplier[experience_code]

        # 분기별 수익 생성 (계절 배수 + 랜덤 노이즈 적용)
        quarterly_revenue = []
        for quarter in range(4):
            # 계절 효과 + 개인별 변동성(±20%)
            seasonal_revenue = base_revenue * self.seasonal_multiplier[quarter]
            noise = np.random.uniform(-0.2, 0.2)
            final_revenue = seasonal_revenue * (1 + noise)

            # 정수로 반올림 (만원 단위)
            quarterly_revenue.append(round(final_revenue))

        # 창작자 데이터 구성
        creator_data = {
            "revenue": quarterly_revenue,
            "genre": genre,
            "experience": experience_years
        }

        return creator_data

    def generate_test_dataset(self) -> List[Dict[str, Any]]:
        """
        전체 테스트 데이터셋을 생성합니다.

        Returns:
            창작자 데이터 리스트
        """
        dataset = []
        for _ in range(self.num_creators):
            dataset.append(self.generate_random_creator())

        return dataset

    def save_test_dataset(self, filename: str) -> None:
        """
        테스트 데이터셋을 파일에 저장합니다.

        Args:
            filename: 저장할 파일 경로
        """
        dataset = self.generate_test_dataset()

        # 인코딩 및 저장
        encoded_data = []
        for creator_data in dataset:
            revenue, metadata = self.encoder.encode_revenue_data(creator_data)
            encoded_data.append((revenue, metadata))

        self.encoder.save_encoded_data(encoded_data, filename)

        # 원본 데이터도 저장 (참조용)
        with open(filename + ".raw", 'w') as f:
            json.dump(dataset, f, indent=2)


# 사용 예시
def example_usage():
    """
    데이터 인코딩 및 테스트 데이터 생성 사용 예시
    """
    # 인코더 초기화
    encoder = RevenueDataEncoder()

    # 샘플 데이터
    sample_data = {
        "revenue": [1500000, 2000000, 1800000, 2500000],  # 원 단위 수익
        "genre": "pop",
        "experience": 3
    }

    # 데이터 인코딩
    normalized_revenue, encoded_metadata = encoder.encode_revenue_data(
        sample_data)
    print("정규화된 수익:", normalized_revenue)
    print("인코딩된 메타데이터:", encoded_metadata)

    # 암호화를 위한 벡터 준비
    combined_vector = encoder.prepare_data_for_encryption(
        normalized_revenue, encoded_metadata)
    print("암호화용 결합 벡터:", combined_vector)

    # 테스트 데이터 생성기 초기화
    generator = TestDataGenerator(encoder, num_creators=10)

    # 랜덤 창작자 데이터 생성
    random_creator = generator.generate_random_creator()
    print("\n랜덤 창작자 데이터:", random_creator)

    # 테스트 데이터셋 생성 및 저장
    generator.save_test_dataset("test_music_creators.json")
    print("\n테스트 데이터셋 생성 완료 (test_music_creators.json)")


if __name__ == "__main__":
    example_usage()
