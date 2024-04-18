from dataclasses import dataclass
from typing import Optional


@dataclass
class StravaAthlete:
  id: int
  username: Optional[str]
  resource_state: int
  firstname: str
  lastname: str
  bio: str
  city: str
  state: str
  country: str
  sex: str
  premium: bool
  summit: bool
  created_at: str
  updated_at: str
  badge_type_id: int
  weight: float
  profile_medium: str
  profile: str
  friend: Optional[bool]
  follower: Optional[bool]


@dataclass
class StravaTokenData:
  token_type: str
  expires_at: int
  expires_in: int
  refresh_token: str
  access_token: str
