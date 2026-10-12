-- Retain historical qualification rows; new source admits only gpt-5.6-sol.
-- Qualification ownership, exact birth, immutability and provider claims stay unchanged.
ALTER TABLE public.gateway_oauth_profile_qualifications
 DROP CONSTRAINT gateway_oauth_profile_qualifications_model_check;
ALTER TABLE public.gateway_oauth_profile_qualifications
 ADD CONSTRAINT gateway_oauth_profile_qualifications_model_check
 CHECK (model IN ('gpt-6.1-sol', 'gpt-5.6-sol'));
